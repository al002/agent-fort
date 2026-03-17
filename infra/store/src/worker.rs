use std::sync::mpsc;
use std::thread;

use rusqlite::Connection;

use crate::{MigrationReport, StoreError, StoreOptions, StoreResult, db, migrations};

#[derive(Debug)]
pub(crate) struct StoreWorker {
    sender: mpsc::Sender<WorkerMessage>,
    join_handle: Option<thread::JoinHandle<()>>,
}

impl StoreWorker {
    pub(crate) fn start(options: StoreOptions) -> StoreResult<(Self, MigrationReport)> {
        let (sender, receiver) = mpsc::channel::<WorkerMessage>();
        let (ready_sender, ready_receiver) = mpsc::channel::<StoreResult<MigrationReport>>();

        let join_handle = thread::Builder::new()
            .name("af-store-worker".to_string())
            .spawn(move || run_worker_loop(options, receiver, ready_sender))
            .map_err(|error| StoreError::Internal(format!("spawn store worker thread: {error}")))?;

        let report = ready_receiver.recv().map_err(|_| {
            StoreError::Internal("store worker terminated before startup completed".to_string())
        })??;

        Ok((
            Self {
                sender,
                join_handle: Some(join_handle),
            },
            report,
        ))
    }

    pub(crate) fn execute<F, R>(&self, operation: F) -> StoreResult<R>
    where
        F: FnOnce(&mut Connection) -> StoreResult<R> + Send + 'static,
        R: Send + 'static,
    {
        let (result_sender, result_receiver) = mpsc::channel::<StoreResult<R>>();
        let job = move |connection: &mut Connection| {
            let result = operation(connection);
            let _ = result_sender.send(result);
        };

        self.sender
            .send(WorkerMessage::Run(Box::new(job)))
            .map_err(|_| StoreError::Internal("store worker channel closed".to_string()))?;
        result_receiver
            .recv()
            .map_err(|_| StoreError::Internal("store worker did not return a result".to_string()))?
    }
}

impl Drop for StoreWorker {
    fn drop(&mut self) {
        let _ = self.sender.send(WorkerMessage::Shutdown);
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
    }
}

enum WorkerMessage {
    Run(Box<dyn Job + Send>),
    Shutdown,
}

trait Job {
    fn run(self: Box<Self>, connection: &mut Connection);
}

impl<F> Job for F
where
    F: FnOnce(&mut Connection) + Send + 'static,
{
    fn run(self: Box<Self>, connection: &mut Connection) {
        (*self)(connection);
    }
}

fn run_worker_loop(
    options: StoreOptions,
    receiver: mpsc::Receiver<WorkerMessage>,
    ready_sender: mpsc::Sender<StoreResult<MigrationReport>>,
) {
    let mut connection = match initialize_store(&options) {
        Ok(connection) => connection,
        Err(error) => {
            let _ = ready_sender.send(Err(error));
            return;
        }
    };

    let migration_report = match migrations::apply_all(&mut connection) {
        Ok(report) => report,
        Err(error) => {
            let _ = ready_sender.send(Err(error));
            return;
        }
    };

    if ready_sender.send(Ok(migration_report)).is_err() {
        return;
    }

    while let Ok(message) = receiver.recv() {
        match message {
            WorkerMessage::Run(job) => job.run(&mut connection),
            WorkerMessage::Shutdown => break,
        }
    }
}

fn initialize_store(options: &StoreOptions) -> StoreResult<Connection> {
    db::open_connection(options)
}
