//! Operational pairing only; this module has no active-trust or application-I/O port.
use super::super::{
    CandidateHello, JournalClock, Role, SAS_FORMAT, SUITE, WORDLIST_HASH,
    codec::{Value, decode, encode},
    evidence::{b, t},
    handshake_binding::{CandidateTranscript, SHARED_EXPORTER_LABEL},
    handshake_machine::Machine,
    handshake_wire::{APPLICATION_ERROR, CandidateGuard, SCHEDULE, Status},
    operational_wire::{CandidateRequest, FrameKind, TransportFrame},
};
use super::*;
use crate::pairing_pending::PendingStore;
use rand::RngCore;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;
#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) struct WireFault {
    pub sequence: usize,
    pub mutation: u8,
}
pub struct HandshakeConfig {
    pub device_name: String,
    pub os: String,
    pub local_rendezvous: [u8; 16],
    pub selected_rendezvous: [u8; 16],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationPrompt {
    pub attempt: [u8; 32],
    pub transcript: [u8; 32],
    pub ui_generation: u64,
    pub words: [String; 4],
    pub names: [String; 2],
    pub fingerprints: [[u8; 32]; 2],
}
pub struct VerificationDecision {
    pub attempt: [u8; 32],
    pub transcript: [u8; 32],
    pub ui_generation: u64,
    pub matches: bool,
}
impl VerificationPrompt {
    pub fn decision(&self, matches: bool) -> VerificationDecision {
        VerificationDecision {
            attempt: self.attempt,
            transcript: self.transcript,
            ui_generation: self.ui_generation,
            matches,
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum HandshakeError {
    Rejected,
    Cancelled,
}
pub struct HandshakeCompletePendingAuthority {
    pub(super) role: Role,
    pub(super) durable_fc_hash: [u8; 32],
    pub(super) local_binding: [u8; 32],
    _channel: ProvisionalChannel,
    _request: Stream,
    failed: Arc<AtomicBool>,
}
struct Completed {
    role: Role,
    durable_fc_hash: [u8; 32],
    local_binding: [u8; 32],
    request: Stream,
    failed: Arc<AtomicBool>,
}
impl HandshakeCompletePendingAuthority {
    pub fn is_protocol_valid(&self) -> bool {
        !self.failed.load(Ordering::Acquire) && self._channel.connection.close_reason().is_none()
    }
    #[cfg(test)]
    pub(super) async fn test_late_extra(&self) {
        let (mut send, _recv) = self._channel.connection.open_bi().await.unwrap();
        send.write_all(&[1]).await.unwrap();
    }
    #[cfg(test)]
    pub(super) async fn test_late_candidate(&mut self) {
        self._request.send.write_all(&[1]).await.unwrap();
    }
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn durable_fc_hash(&self) -> Option<&[u8; 32]> {
        self.is_protocol_valid().then_some(&self.durable_fc_hash)
    }
    pub fn local_binding(&self) -> &[u8; 32] {
        &self.local_binding
    }
}
fn fresh<const N: usize>() -> Result<[u8; N], Invalid> {
    let mut out = [0; N];
    rand::rngs::OsRng
        .try_fill_bytes(&mut out)
        .map_err(|_| Invalid)?;
    Ok(out)
}
async fn bounded<T, E>(
    future: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, Invalid> {
    tokio::time::timeout(Duration::from_secs(30), future)
        .await
        .map_err(|_| Invalid)?
        .map_err(|_| Invalid)
}
struct LiveClock {
    epoch: [u8; 16],
    origin: Instant,
}
impl LiveClock {
    fn new() -> Result<Self, Invalid> {
        Ok(Self {
            epoch: fresh()?,
            origin: Instant::now(),
        })
    }
    fn now(&self) -> Result<JournalClock, Invalid> {
        Ok(JournalClock {
            boot: self.epoch,
            monotonic_ms: self
                .origin
                .elapsed()
                .as_millis()
                .try_into()
                .map_err(|_| Invalid)?,
            utc_seconds: utc()?,
        })
    }
}
struct Stream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    clean: bool,
}
#[cfg(test)]
pub(super) fn reject_test_stream(pair: (quinn::SendStream, quinn::RecvStream)) {
    drop(Stream::new(pair));
}
impl Stream {
    fn new((send, recv): (quinn::SendStream, quinn::RecvStream)) -> Self {
        Self {
            send,
            recv,
            clean: false,
        }
    }
}
impl Drop for Stream {
    fn drop(&mut self) {
        if !self.clean {
            let _ = self.send.reset(APPLICATION_ERROR.into());
            let _ = self.recv.stop(APPLICATION_ERROR.into());
        }
    }
}
async fn read_exact(recv: &mut quinn::RecvStream, n: usize) -> Result<Vec<u8>, Invalid> {
    let mut raw = vec![0; n];
    recv.read_exact(&mut raw).await.map_err(|_| Invalid)?;
    Ok(raw)
}
async fn candidate_record(recv: &mut quinn::RecvStream) -> Result<Vec<u8>, Invalid> {
    let mut raw = read_exact(recv, 15).await?;
    if &raw[..8] != b"CSF12P2\0" || raw[8..10] != 2u16.to_be_bytes() {
        return Err(Invalid);
    }
    let cap = match raw[10] {
        1 => 1024,
        2 => 4096,
        _ => return Err(Invalid),
    };
    let n = u32::from_be_bytes(raw[11..15].try_into().map_err(|_| Invalid)?) as usize;
    if n == 0 || n > cap {
        return Err(Invalid);
    }
    raw.extend(read_exact(recv, n).await?);
    Ok(raw)
}
async fn control_record(recv: &mut quinn::RecvStream) -> Result<Vec<u8>, Invalid> {
    let mut raw = read_exact(recv, 20).await?;
    let n = u32::from_be_bytes(raw[16..20].try_into().map_err(|_| Invalid)?) as usize;
    if n == 0 || n > 16384 {
        return Err(Invalid);
    }
    raw.extend(read_exact(recv, n).await?);
    Ok(raw)
}
async fn eof(recv: &mut quinn::RecvStream) -> Result<(), Invalid> {
    let mut byte = [0];
    if recv.read(&mut byte).await.map_err(|_| Invalid)?.is_some() {
        return Err(Invalid);
    }
    Ok(())
}
// A requester's FIN is neither required nor a response-FIN event. Any DATA is
// forbidden, even if it arrives while the other candidate stream is active.
async fn watch_request(recv: &mut quinn::RecvStream) -> Invalid {
    let mut byte = [0];
    match recv.read(&mut byte).await {
        Ok(None) => std::future::pending().await,
        _ => Invalid,
    }
}
fn candidate(
    config: &HandshakeConfig,
    request: &CandidateRequest,
    cert: &[u8],
) -> Result<Vec<u8>, Invalid> {
    if request.rendezvous != config.local_rendezvous {
        return Err(Invalid);
    }
    let mut suites = vec![0, 1, 0, SUITE.len() as u8];
    suites.extend(SUITE.as_bytes());
    let raw = encode(
        "candidate-hello",
        &[
            b(&config.local_rendezvous),
            b(&request.nonce),
            b(&fresh::<16>()?),
            t(&config.device_name),
            t(&config.os),
            b(&suites),
            b(&hash(cert)),
            Value::Number(30_000),
        ],
    )?;
    CandidateHello::decode(&raw)?;
    Ok(raw)
}
fn hello(candidate: &[u8], cert: &[u8]) -> Result<Vec<u8>, Invalid> {
    let c = decode("candidate-hello", candidate, &[2, 2, 2, 3, 3, 2, 2, 1])?;
    encode(
        "hello",
        &[
            Value::Number(2),
            b(&fresh::<16>()?),
            c[0].clone(),
            b(&fresh::<16>()?),
            b(&hash(candidate)),
            c[1].clone(),
            c[2].clone(),
            c[3].clone(),
            b(cert),
            t(SUITE),
            t(SAS_FORMAT),
            b(&WORDLIST_HASH),
            t("compare_v2_required"),
            Value::Number(300),
        ],
    )
}
async fn exchange(
    stream: &mut Stream,
    requester: Role,
    local: Role,
    config: &HandshakeConfig,
    cert: &[u8],
    guard: &mut CandidateGuard,
) -> Result<(Vec<u8>, Vec<u8>), Invalid> {
    let a = requester.index() as u8 + 1;
    let b_role = 3 - a;
    let request = if requester == local {
        let payload =
            CandidateRequest::new(fresh()?, config.selected_rendezvous, fresh()?).encode()?;
        let raw = TransportFrame {
            kind: FrameKind::CandidateRequest,
            payload: payload.clone(),
        }
        .encode()?;
        if !guard.receive(1, a, a, &raw, |_, _| true) {
            return Err(Invalid);
        }
        stream.send.write_all(&raw).await.map_err(|_| Invalid)?;
        payload
    } else {
        let raw = candidate_record(&mut stream.recv).await?;
        if !guard.receive(1, a, a, &raw, |_, _| true) {
            return Err(Invalid);
        }
        TransportFrame::decode(&raw)?.payload
    };
    let response = if requester != local {
        let payload = candidate(config, &CandidateRequest::decode(&request)?, cert)?;
        let raw = TransportFrame {
            kind: FrameKind::CandidateHello,
            payload: payload.clone(),
        }
        .encode()?;
        if !guard.receive(2, a, b_role, &raw, |_, _| true) {
            return Err(Invalid);
        }
        stream.send.write_all(&raw).await.map_err(|_| Invalid)?;
        stream.send.finish().map_err(|_| Invalid)?;
        payload
    } else {
        let raw = candidate_record(&mut stream.recv).await?;
        if !guard.receive(2, a, b_role, &raw, |_, _| true) {
            return Err(Invalid);
        }
        eof(&mut stream.recv).await?;
        TransportFrame::decode(&raw)?.payload
    };
    if !guard.receive(3, a, b_role, &[], |_, _| true) {
        return Err(Invalid);
    }
    Ok((request, response))
}
impl ProvisionalChannel {
    async fn write_control(
        &self,
        send: &mut quinn::SendStream,
        raw: &[u8],
        _seq: usize,
    ) -> Result<(), HandshakeError> {
        #[cfg(test)]
        if matches!(_seq, 12 | 13)
            && std::env::var("CSF12_BILATERAL_EMIT_CRASH").as_deref() == Ok("before")
        {
            std::process::exit(91);
        }
        #[cfg(test)]
        if let Some(fault) = self.fault
            && fault.sequence == _seq
        {
            let mut raw = raw.to_vec();
            match fault.mutation {
                0 => {
                    for byte in raw {
                        send.write_all(&[byte])
                            .await
                            .map_err(|_| HandshakeError::Rejected)?;
                        tokio::task::yield_now().await;
                    }
                    return Ok(());
                }
                1 => raw.push(1),
                2 => raw[16..20].copy_from_slice(&16385u32.to_be_bytes()),
                3 => raw[11] = 3 - raw[11],
                4 => raw[12..16].copy_from_slice(&((_seq + 1) as u32).to_be_bytes()),
                5 => {
                    raw.truncate(raw.len() / 2);
                    send.write_all(&raw)
                        .await
                        .map_err(|_| HandshakeError::Rejected)?;
                    send.finish().map_err(|_| HandshakeError::Rejected)?;
                    return Ok(());
                }
                6 => raw.extend(raw.clone()),
                _ => return Err(HandshakeError::Rejected),
            }
            return send
                .write_all(&raw)
                .await
                .map_err(|_| HandshakeError::Rejected);
        }
        send.write_all(raw)
            .await
            .map_err(|_| HandshakeError::Rejected)?;
        #[cfg(test)]
        if matches!(_seq, 12 | 13)
            && std::env::var("CSF12_BILATERAL_EMIT_CRASH").as_deref() == Ok("after")
        {
            std::process::exit(91);
        }
        Ok(())
    }
    /// One consumed sealed channel, two logical requester streams, one exporter.
    /// No RecoveryAuthority, active trust, admission or application stream is available.
    pub async fn handshake<F, Fut>(
        mut self,
        config: HandshakeConfig,
        store: &PendingStore,
        confirm: F,
    ) -> Result<HandshakeCompletePendingAuthority, HandshakeError>
    where
        F: FnOnce(VerificationPrompt) -> Fut,
        Fut: std::future::Future<Output = VerificationDecision>,
    {
        let result =
            tokio::time::timeout(Duration::from_secs(300), self.run(config, store, confirm)).await;
        match result {
            Ok(Ok(done)) => Ok(HandshakeCompletePendingAuthority {
                role: done.role,
                durable_fc_hash: done.durable_fc_hash,
                local_binding: done.local_binding,
                _channel: self,
                _request: done.request,
                failed: done.failed,
            }),
            Ok(Err(HandshakeError::Cancelled)) => Err(HandshakeError::Cancelled),
            _ => {
                self.connection
                    .close(APPLICATION_ERROR.into(), b"pairing rejected");
                Err(HandshakeError::Rejected)
            }
        }
    }
    fn active(&self) -> Result<std::sync::MutexGuard<'_, bool>, Invalid> {
        let active = self.scope.lock().map_err(|_| Invalid)?;
        if !*active
            || self.connection.close_reason().is_some()
            || self.id != format!("quic-{}", self.connection.stable_id())
        {
            return Err(Invalid);
        }
        Ok(active)
    }
    async fn run<F, Fut>(
        &mut self,
        config: HandshakeConfig,
        store: &PendingStore,
        confirm: F,
    ) -> Result<Completed, HandshakeError>
    where
        F: FnOnce(VerificationPrompt) -> Fut,
        Fut: std::future::Future<Output = VerificationDecision>,
    {
        let reject = |_: Invalid| HandshakeError::Rejected;
        {
            let _active = self.active().map_err(reject)?;
            if self.attempted {
                return Err(HandshakeError::Rejected);
            }
        }
        self.attempted = true;
        let clock = LiveClock::new().map_err(reject)?;
        let version = store.version().map_err(|_| HandshakeError::Rejected)?;
        if self.local_identity.cert.len() != 1 {
            return Err(HandshakeError::Rejected);
        }
        let cert = self.local_identity.cert[0].as_ref();
        let local_fp = hash(cert);
        let peer_fp = hash(&self.leaf);
        if local_fp == peer_fp {
            return Err(HandshakeError::Rejected);
        }
        let role = if local_fp < peer_fp { Role::A } else { Role::B };
        let mut guard = CandidateGuard::new();
        let mut first = Stream::new(
            bounded(async {
                if role == Role::A {
                    self.connection.open_bi().await
                } else {
                    self.connection.accept_bi().await
                }
            })
            .await
            .map_err(|_| HandshakeError::Rejected)?,
        );
        let (request_a, candidate_b) = bounded(exchange(
            &mut first,
            Role::A,
            role,
            &config,
            cert,
            &mut guard,
        ))
        .await
        .map_err(reject)?;
        // The first response must be FIN before the second logical requester opens.
        let next = async {
            let mut second = Stream::new(
                bounded(async {
                    if role == Role::B {
                        self.connection.open_bi().await
                    } else {
                        self.connection.accept_bi().await
                    }
                })
                .await
                .map_err(|_| Invalid)?,
            );
            let pair = bounded(exchange(
                &mut second,
                Role::B,
                role,
                &config,
                cert,
                &mut guard,
            ))
            .await?;
            Ok::<_, Invalid>((second, pair))
        };
        let (mut second, (request_b, candidate_a)) = if role == Role::B {
            tokio::select! {biased;_ = watch_request(&mut first.recv)=>return Err(HandshakeError::Rejected),result=next=>result.map_err(reject)?}
        } else {
            next.await.map_err(reject)?
        };
        if !guard.complete() {
            return Err(HandshakeError::Rejected);
        }
        if clock.now().map_err(reject)?.monotonic_ms >= 30_000 {
            return Err(HandshakeError::Rejected);
        }
        let observed = if role == Role::A {
            [cert.to_vec(), self.leaf.clone()]
        } else {
            [self.leaf.clone(), cert.to_vec()]
        };
        let transcript = CandidateTranscript::new(
            [request_a, request_b],
            [candidate_a, candidate_b],
            observed,
            utc().map_err(reject)?,
        )
        .map_err(reject)?;
        let input = BindingInput::new(
            &transcript.requests[role.index()],
            &transcript.candidates[1 - role.index()],
            &self.leaf,
            &self.id,
            self.generation,
            ALPN,
        )
        .map_err(reject)?;
        self.owner.replay.consume_input(&input).map_err(reject)?;
        let mut exporter = Zeroizing::new([0; 32]);
        self.connection
            .export_keying_material(
                exporter.as_mut(),
                SHARED_EXPORTER_LABEL,
                &transcript.exporter_context().map_err(reject)?,
            )
            .map_err(|_| HandshakeError::Rejected)?;
        let binding = transcript
            .local_binding(role, &self.id, self.generation, &exporter)
            .map_err(reject)?;
        let own_hello = hello(&transcript.candidates[role.index()], cert).map_err(reject)?;
        let mut machine = Machine::new(
            transcript,
            role,
            own_hello,
            Zeroizing::new(fresh().map_err(reject)?),
            Zeroizing::new(fresh().map_err(reject)?),
            self.generation,
            version,
            clock.now().map_err(reject)?,
            &self.id,
            self.generation,
        )
        .map_err(reject)?;
        let signer = self
            .local_identity
            .key
            .choose_scheme(&[rustls::SignatureScheme::ED25519])
            .ok_or(HandshakeError::Rejected)?;
        let sign = |body: &[u8]| signer.sign(body).map_err(|_| Invalid);
        let watch = if role == Role::A {
            &mut second.recv
        } else {
            &mut first.recv
        };
        let control = async {
            let pair = bounded(async {
                if role == Role::A {
                    self.connection.open_bi().await
                } else {
                    self.connection.accept_bi().await
                }
            })
            .await
            .map_err(|_| HandshakeError::Rejected)?;
            let mut control = Stream::new(pair);
            let protocol = async {
                let mut confirm = Some(confirm);
                while machine.sequence() < 17 {
                    // Yield to the biased request/extra-stream monitors before
                    // each durable transition, not just between network reads.
                    tokio::task::yield_now().await;
                    let seq = machine.sequence();
                    if seq == 8 {
                        let prompt = machine
                            .prompt(clock.now().map_err(reject)?)
                            .map_err(reject)?;
                        let decision =
                            confirm.take().ok_or(HandshakeError::Rejected)?(prompt.clone()).await;
                        if decision.attempt != prompt.attempt
                            || decision.transcript != prompt.transcript
                            || decision.ui_generation != prompt.ui_generation
                        {
                            return Err(HandshakeError::Rejected);
                        }
                        if !decision.matches {
                            let raw = machine
                                .cancel_local(&sign, store, clock.now().map_err(reject)?)
                                .map_err(reject)?;
                            control
                                .send
                                .write_all(&raw)
                                .await
                                .map_err(|_| HandshakeError::Rejected)?;
                            control
                                .send
                                .finish()
                                .map_err(|_| HandshakeError::Rejected)?;
                            return Err(HandshakeError::Cancelled);
                        }
                        machine
                            .confirm(true, clock.now().map_err(reject)?)
                            .map_err(reject)?;
                    }
                    if SCHEDULE[seq].1 == role.index() as u8 + 1 {
                        let raw = {
                            let _active = self.active().map_err(reject)?;
                            machine
                                .next_local(&sign, store, clock.now().map_err(reject)?)
                                .map_err(reject)?
                        };
                        bounded(self.write_control(&mut control.send, &raw, seq))
                            .await
                            .map_err(reject)?;
                    } else {
                        let raw = bounded(control_record(&mut control.recv))
                            .await
                            .map_err(reject)?;
                        let _active = self.active().map_err(reject)?;
                        machine
                            .receive_remote(&raw, store, clock.now().map_err(reject)?)
                            .map_err(reject)?;
                        if machine.status() == Status::Cancelled {
                            return Err(HandshakeError::Cancelled);
                        }
                    }
                }
                control
                    .send
                    .finish()
                    .map_err(|_| HandshakeError::Rejected)?;
                if !machine.half_close(role) {
                    return Err(HandshakeError::Rejected);
                }
                bounded(eof(&mut control.recv)).await.map_err(reject)?;
                if !machine.half_close(if role == Role::A { Role::B } else { Role::A }) {
                    return Err(HandshakeError::Rejected);
                }
                bounded(control.send.stopped())
                    .await
                    .map_err(|_| HandshakeError::Rejected)?;
                machine.durable_fc().ok_or(HandshakeError::Rejected)
            };
            let result = tokio::select! {biased;
                extra=self.connection.accept_bi()=>{if let Ok(pair)=extra{drop(Stream::new(pair));}Err(HandshakeError::Rejected)},
                extra=self.connection.accept_uni()=>{if let Ok(mut stream)=extra{let _=stream.stop(APPLICATION_ERROR.into());}Err(HandshakeError::Rejected)},
                result=protocol=>result,
            };
            if matches!(&result, Ok(_) | Err(HandshakeError::Cancelled)) {
                control.clean = true;
            }
            result
        };
        let result = tokio::select! {biased;_ = watch_request(watch)=>Err(HandshakeError::Rejected),result=control=>result};
        if result.is_err() {
            machine.reject();
            machine.dispose_pending(store);
        }
        if matches!(&result, Ok(_) | Err(HandshakeError::Cancelled)) {
            first.clean = true;
            second.clean = true;
        }
        let fc = result?;
        let (request, mut incoming) = if role == Role::A {
            (first, second)
        } else {
            (second, first)
        };
        let failed = Arc::new(AtomicBool::new(false));
        let signal = failed.clone();
        let connection = self.connection.clone();
        // Successful control FIN does not forgive DATA on the request half,
        // extra streams or a later protocol error. Keep this monitor sealed.
        tokio::spawn(async move {
            let violation = tokio::select! {biased;
                _=connection.closed()=>false,
                _=watch_request(&mut incoming.recv)=>true,
                extra=connection.accept_bi()=>{if let Ok(pair)=extra{drop(Stream::new(pair));}true},
                extra=connection.accept_uni()=>{if let Ok(mut recv)=extra{let _=recv.stop(APPLICATION_ERROR.into());}true},
            };
            if violation {
                signal.store(true, Ordering::Release);
                incoming.clean = false;
                drop(incoming);
                connection.close(
                    APPLICATION_ERROR.into(),
                    b"post-completion pairing violation",
                );
            }
        });
        Ok(Completed {
            role,
            durable_fc_hash: fc,
            local_binding: binding,
            request,
            failed,
        })
    }
}
