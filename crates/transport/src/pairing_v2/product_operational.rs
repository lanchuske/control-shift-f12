use super::{Invalid, operational_session::LocalOperationalConsent};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::oneshot;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalPrompt {
    pub words: [String; 4],
    pub remaining_ms: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationalOutcome {
    Verified,
    Rejected,
    Expired,
    Revoked,
    RemoteOutcomeUnknown,
}

/// Redacted, one-use local decision port. It contains no transport handle,
/// address, certificate pin, transcript hash, or durable admission token.
pub struct ProductOperationalAttempt {
    prompt: Option<oneshot::Receiver<OperationalPrompt>>,
    decision: Option<oneshot::Sender<bool>>,
    completion: Option<oneshot::Receiver<OperationalOutcome>>,
    local_outcome: Option<OperationalOutcome>,
}

impl ProductOperationalAttempt {
    pub async fn prompt(&mut self) -> Result<OperationalPrompt, Invalid> {
        self.prompt
            .take()
            .ok_or(Invalid)?
            .await
            .map_err(|_| Invalid)
    }

    pub fn decide(&mut self, matches: bool) -> Result<(), Invalid> {
        let decision = self.decision.take().ok_or(Invalid)?;
        decision.send(matches).map_err(|_| Invalid)?;
        if !matches {
            self.local_outcome = Some(OperationalOutcome::Rejected);
        }
        Ok(())
    }

    pub fn outcome(&self) -> Option<OperationalOutcome> {
        self.local_outcome
    }

    pub async fn finish(mut self) -> OperationalOutcome {
        let remote = match self.completion.take() {
            Some(completion) => completion
                .await
                .unwrap_or(OperationalOutcome::RemoteOutcomeUnknown),
            None => OperationalOutcome::RemoteOutcomeUnknown,
        };
        self.local_outcome.unwrap_or(remote)
    }

    pub(crate) fn start(
        attempt: super::operational_session::OperationalAttempt,
    ) -> Result<Self, Invalid> {
        let (prompt_send, prompt) = oneshot::channel();
        let (decision, decision_recv) = oneshot::channel();
        let (completion_send, completion) = oneshot::channel();
        let rejected = Arc::new(AtomicBool::new(false));
        let rejected_in_callback = Arc::clone(&rejected);
        let started = tokio::time::Instant::now();
        tokio::spawn(async move {
            let result = attempt
                .complete_with_local_consent(
                    move |preconfirm, commitment, remaining_ms| async move {
                        let words = super::sas_words(&preconfirm)?;
                        prompt_send
                            .send(OperationalPrompt {
                                words,
                                remaining_ms,
                            })
                            .map_err(|_| Invalid)?;
                        match decision_recv.await {
                            Ok(true) => {
                                Ok(LocalOperationalConsent::approved(preconfirm, commitment))
                            }
                            Ok(false) => {
                                rejected_in_callback.store(true, Ordering::Release);
                                Err(Invalid)
                            }
                            Err(_) => Err(Invalid),
                        }
                    },
                )
                .await;
            let outcome = if result.is_ok() {
                OperationalOutcome::Verified
            } else if rejected.load(Ordering::Acquire) {
                OperationalOutcome::Rejected
            } else if started.elapsed() >= std::time::Duration::from_secs(30) {
                OperationalOutcome::Expired
            } else {
                OperationalOutcome::RemoteOutcomeUnknown
            };
            let _ = completion_send.send(outcome);
        });
        Ok(Self {
            prompt: Some(prompt),
            decision: Some(decision),
            completion: Some(completion),
            local_outcome: None,
        })
    }
}

#[cfg(test)]
fn decision_bridge(
    preconfirm: [u8; 32],
    commitment: [u8; 32],
    remaining_ms: u32,
) -> Result<
    (
        ProductOperationalAttempt,
        oneshot::Receiver<Result<LocalOperationalConsent, Invalid>>,
    ),
    Invalid,
> {
    if remaining_ms == 0 {
        return Err(Invalid);
    }
    let words = super::sas_words(&preconfirm)?;
    let (prompt_send, prompt) = oneshot::channel();
    let (decision, decision_recv) = oneshot::channel();
    let (consent_send, consent) = oneshot::channel();
    prompt_send
        .send(OperationalPrompt {
            words,
            remaining_ms,
        })
        .map_err(|_| Invalid)?;
    tokio::spawn(async move {
        let result = match decision_recv.await {
            Ok(true) => Ok(LocalOperationalConsent::approved(preconfirm, commitment)),
            Ok(false) | Err(_) => Err(Invalid),
        };
        let _ = consent_send.send(result);
    });
    Ok((
        ProductOperationalAttempt {
            prompt: Some(prompt),
            decision: Some(decision),
            completion: None,
            local_outcome: None,
        },
        consent,
    ))
}

#[cfg(test)]
mod tests {
    use super::{OperationalOutcome, OperationalPrompt, decision_bridge};

    #[tokio::test]
    async fn prompt_is_redacted_and_decision_is_single_use() {
        let preconfirm = [7; 32];
        let commitment = [8; 32];
        let (mut product, consent) = decision_bridge(preconfirm, commitment, 12_345).unwrap();

        assert_eq!(
            product.prompt().await.unwrap(),
            OperationalPrompt {
                words: crate::pairing_v2::sas_words(&preconfirm).unwrap(),
                remaining_ms: 12_345,
            }
        );
        assert!(product.decide(true).is_ok());
        assert!(product.decide(true).is_err());
        assert!(consent.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn mismatch_is_terminal_and_never_constructs_consent() {
        let (mut product, consent) = decision_bridge([9; 32], [10; 32], 30_000).unwrap();
        let _ = product.prompt().await.unwrap();

        assert!(product.decide(false).is_ok());
        assert_eq!(product.outcome(), Some(OperationalOutcome::Rejected));
        assert!(consent.await.unwrap().is_err());
    }
}
