use std::time::Duration;

use crate::{PolicyInfraResult, PolicyWatchEvent};

pub fn merge_debounced<F>(
    mut event: PolicyWatchEvent,
    debounce_window: Duration,
    mut recv_next: F,
) -> PolicyInfraResult<PolicyWatchEvent>
where
    F: FnMut(Duration) -> PolicyInfraResult<Option<PolicyWatchEvent>>,
{
    loop {
        match recv_next(debounce_window)? {
            Some(next) if next.root == event.root => {
                event.paths.extend(next.paths);
            }
            Some(_) => {}
            None => break,
        }
    }

    Ok(event)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::time::Duration;

    use super::*;
    use crate::PolicyWatchEvent;

    #[test]
    fn merges_multiple_events_received_within_debounce_window() {
        let mut queued = VecDeque::from([
            PolicyWatchEvent {
                root: "/tmp/policies".into(),
                paths: vec!["/tmp/policies/a.yaml".into()],
            },
            PolicyWatchEvent {
                root: "/tmp/policies".into(),
                paths: vec!["/tmp/policies/b.yaml".into()],
            },
        ]);

        let merged = merge_debounced(
            queued.pop_front().expect("first event"),
            Duration::from_millis(1),
            |_| Ok(queued.pop_front()),
        )
        .expect("merge events");

        assert_eq!(merged.paths.len(), 2);
    }
}
