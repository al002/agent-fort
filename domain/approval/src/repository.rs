use crate::errors::ApprovalRepositoryError;
use crate::model::{Approval, NewApproval, RespondApprovalCommand};

pub trait ApprovalRepository: Send + Sync {
    fn create_approval(&self, command: NewApproval) -> Result<Approval, ApprovalRepositoryError>;

    fn get_approval(
        &self,
        session_id: &str,
        approval_id: &str,
    ) -> Result<Approval, ApprovalRepositoryError>;

    fn respond_approval(
        &self,
        command: RespondApprovalCommand,
    ) -> Result<Approval, ApprovalRepositoryError>;

    fn expire_pending_approvals(
        &self,
        now_ms: u64,
        limit: u32,
    ) -> Result<Vec<Approval>, ApprovalRepositoryError>;
}
