//! Closed, redacted data shared with future local native presentation hosts.
//!
//! This module is intentionally a value contract only. It does not launch a
//! process, open a pipe, listen on a socket, pair a peer, or grant input or
//! clipboard capabilities.

use crate::control_api;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, io::Write};

pub const UI_SCHEMA_VERSION: u16 = 1;
const MAX_VISIBLE_ITEMS: usize = 32;
const MAX_REPLAYED_REQUESTS: usize = 256;
const MAX_HANDLE_BYTES: usize = 64;
const MAX_ALIGNMENT: i32 = 100_000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UiContractError {
    #[error("ui contract: unsupported schema")]
    UnsupportedSchema,
    #[error("ui contract: invalid opaque handle")]
    InvalidHandle,
    #[error("ui contract: invalid SAS")]
    InvalidSas,
    #[error("ui contract: invalid remaining duration")]
    InvalidRemainingDuration,
    #[error("ui contract: SAS is outside an operational confirmation")]
    SasOutsideV01,
    #[error("ui contract: operational confirmation is missing its SAS")]
    SasMissingV01,
    #[error("ui contract: too many diagnostics")]
    TooManyDiagnostics,
    #[error("ui contract: too many candidates")]
    TooManyCandidates,
    #[error("ui contract: too many relationships")]
    TooManyRelationships,
    #[error("ui contract: too many displays")]
    TooManyDisplays,
    #[error("ui contract: invalid display")]
    InvalidDisplay,
    #[error("ui contract: invalid alignment")]
    InvalidAlignment,
    #[error("ui contract: invalid command")]
    InvalidCommand,
    #[error("ui contract: request ID conflict")]
    RequestIdConflict,
    #[error("ui contract: request limit")]
    RequestLimit,
    #[error("ui contract: bounded control frame rejected")]
    ControlFrame,
}

fn deserialize_error<E: serde::de::Error>(error: UiContractError) -> E {
    E::custom(error.to_string())
}

fn validate_handle(value: &str) -> Result<(), UiContractError> {
    if value.is_empty()
        || value.len() > MAX_HANDLE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(UiContractError::InvalidHandle);
    }
    Ok(())
}

macro_rules! opaque_handle {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
        pub struct $name(String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = UiContractError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                validate_handle(&value)?;
                Ok(Self(value))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                String::deserialize(deserializer)?
                    .try_into()
                    .map_err(deserialize_error)
            }
        }
    };
}

opaque_handle!(CandidateHandle);
opaque_handle!(RelationshipHandle);
opaque_handle!(DisplayHandle);
opaque_handle!(RequestId);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SasCode(Vec<String>);

impl TryFrom<Vec<String>> for SasCode {
    type Error = UiContractError;

    fn try_from(groups: Vec<String>) -> Result<Self, Self::Error> {
        if !(2..=8).contains(&groups.len())
            || groups.iter().any(|group| {
                group.is_empty()
                    || group.len() > 8
                    || !group.bytes().all(|byte| byte.is_ascii_alphanumeric())
            })
        {
            return Err(UiContractError::InvalidSas);
        }
        Ok(Self(groups))
    }
}

impl<'de> Deserialize<'de> for SasCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<String>::deserialize(deserializer)?
            .try_into()
            .map_err(deserialize_error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UiState {
    NotStarted,
    Browsing,
    CandidateSelected,
    BootstrapConnecting,
    BootstrapSasPending,
    BootstrapReceiptPrepared,
    ConfirmedRelationship,
    V01Pending,
    InventoryCurrent,
    ProposalLocal,
    ProposalRemoteReview,
    LayoutPreparePending,
    LayoutCommitPending,
    FinalizePending,
    LayoutCommitted,
    LayoutAbortLocked,
    RemoteOutcomeUnknown,
    LayoutRecoveryPending,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticId {
    Runtime,
    Input,
    Clipboard,
    Displays,
    Relationship,
    Session,
    Layout,
    Policy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticLabel {
    Runtime,
    Input,
    Clipboard,
    Displays,
    Relationship,
    Session,
    Layout,
    Policy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticState {
    Pass,
    Fail,
    Unknown,
    NotConfigured,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticDetail {
    Ready,
    NotMeasured,
    NotConfigured,
    Stale,
    Unavailable,
    PolicyBlocked,
    Fault,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticAction {
    Refresh,
    ReviewLocalPermission,
    ReviewPrivateNetwork,
    Retry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticRow {
    pub id: DiagnosticId,
    pub label: DiagnosticLabel,
    pub state: DiagnosticState,
    pub detail: DiagnosticDetail,
    pub action: Option<DiagnosticAction>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateCompatibility {
    Compatible,
    NeedsUpdate,
    Incompatible,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateFreshness {
    Current,
    Stale,
    Gone,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateView {
    pub handle: CandidateHandle,
    pub compatibility: CandidateCompatibility,
    pub freshness: CandidateFreshness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipState {
    Active,
    Revoked,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationshipView {
    pub handle: RelationshipHandle,
    pub state: RelationshipState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemainingDuration {
    MoreThanTenSeconds,
    Seconds(u8),
}

impl RemainingDuration {
    fn validate(self) -> Result<(), UiContractError> {
        match self {
            Self::MoreThanTenSeconds | Self::Seconds(1..=10) => Ok(()),
            Self::Seconds(_) => Err(UiContractError::InvalidRemainingDuration),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct V01View {
    pub code: SasCode,
    pub remaining: RemainingDuration,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct V01ViewWire {
    code: SasCode,
    remaining: RemainingDuration,
}

impl V01View {
    fn validate(&self) -> Result<(), UiContractError> {
        self.remaining.validate()
    }
}

impl<'de> Deserialize<'de> for V01View {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = V01ViewWire::deserialize(deserializer)?;
        let value = Self {
            code: wire.code,
            remaining: wire.remaining,
        };
        value.validate().map_err(deserialize_error)?;
        Ok(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryProvenance {
    MeasuredLocally,
    NotReported,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisplayOrientation {
    Landscape,
    Portrait,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisplayView {
    pub handle: DisplayHandle,
    pub logical_width: u32,
    pub logical_height: u32,
    pub scale_milli: u16,
    pub orientation: DisplayOrientation,
    pub physical_width_mm: Option<u32>,
    pub physical_height_mm: Option<u32>,
}

impl DisplayView {
    fn validate(&self) -> Result<(), UiContractError> {
        let physical_pair = self.physical_width_mm.is_some() == self.physical_height_mm.is_some();
        let physical_valid = self
            .physical_width_mm
            .zip(self.physical_height_mm)
            .is_none_or(|(width, height)| {
                (1..=10_000).contains(&width) && (1..=10_000).contains(&height)
            });
        if !(1..=32_768).contains(&self.logical_width)
            || !(1..=32_768).contains(&self.logical_height)
            || !(250..=8_000).contains(&self.scale_milli)
            || !physical_pair
            || !physical_valid
        {
            return Err(UiContractError::InvalidDisplay);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryView {
    pub generation: u64,
    pub provenance: InventoryProvenance,
    pub displays: Vec<DisplayView>,
}

impl InventoryView {
    fn validate(&self) -> Result<(), UiContractError> {
        if self.displays.len() > MAX_VISIBLE_ITEMS {
            return Err(UiContractError::TooManyDisplays);
        }
        for display in &self.displays {
            display.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayoutState {
    NotConfigured,
    Draft,
    ProposalLocal,
    ProposalRemoteReview,
    PreparePending,
    CommitPending,
    FinalizePending,
    Committed,
    AbortLocked,
    RemoteOutcomeUnknown,
    RecoveryPending,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutView {
    pub state: LayoutState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapabilityView {
    input_enabled: bool,
    clipboard_enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityViewWire {
    input_enabled: bool,
    clipboard_enabled: bool,
}

impl CapabilityView {
    pub fn all_disabled() -> Self {
        Self {
            input_enabled: false,
            clipboard_enabled: false,
        }
    }

    pub fn input_enabled(&self) -> bool {
        self.input_enabled
    }

    pub fn clipboard_enabled(&self) -> bool {
        self.clipboard_enabled
    }

    pub(crate) fn from_independent_owner(input_enabled: bool, clipboard_enabled: bool) -> Self {
        Self {
            input_enabled,
            clipboard_enabled,
        }
    }
}

impl<'de> Deserialize<'de> for CapabilityView {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CapabilityViewWire::deserialize(deserializer)?;
        Ok(Self::from_independent_owner(
            wire.input_enabled,
            wire.clipboard_enabled,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UiSnapshot {
    pub schema_version: u16,
    pub generation: u64,
    pub state: UiState,
    pub diagnostics: Vec<DiagnosticRow>,
    pub candidates: Vec<CandidateView>,
    pub confirmed: Vec<RelationshipView>,
    pub v01: Option<V01View>,
    pub inventory: Option<InventoryView>,
    pub layout: LayoutView,
    pub capabilities: CapabilityView,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UiSnapshotWire {
    schema_version: u16,
    generation: u64,
    state: UiState,
    diagnostics: Vec<DiagnosticRow>,
    candidates: Vec<CandidateView>,
    confirmed: Vec<RelationshipView>,
    v01: Option<V01View>,
    inventory: Option<InventoryView>,
    layout: LayoutView,
    capabilities: CapabilityView,
}

impl UiSnapshot {
    pub fn validate(&self) -> Result<(), UiContractError> {
        if self.schema_version != UI_SCHEMA_VERSION {
            return Err(UiContractError::UnsupportedSchema);
        }
        if self.diagnostics.len() > MAX_VISIBLE_ITEMS {
            return Err(UiContractError::TooManyDiagnostics);
        }
        if self.candidates.len() > MAX_VISIBLE_ITEMS {
            return Err(UiContractError::TooManyCandidates);
        }
        if self.confirmed.len() > MAX_VISIBLE_ITEMS {
            return Err(UiContractError::TooManyRelationships);
        }
        match (self.state, &self.v01) {
            (UiState::V01Pending, Some(v01)) => v01.validate()?,
            (UiState::V01Pending, None) => return Err(UiContractError::SasMissingV01),
            (_, Some(_)) => return Err(UiContractError::SasOutsideV01),
            (_, None) => {}
        }
        if let Some(inventory) = &self.inventory {
            inventory.validate()?;
        }
        Ok(())
    }

    pub fn write_framed(&self, writer: &mut impl Write) -> Result<(), UiContractError> {
        self.validate()?;
        control_api::write_message(writer, self).map_err(|_| UiContractError::ControlFrame)
    }
}

impl<'de> Deserialize<'de> for UiSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = UiSnapshotWire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            generation: wire.generation,
            state: wire.state,
            diagnostics: wire.diagnostics,
            candidates: wire.candidates,
            confirmed: wire.confirmed,
            v01: wire.v01,
            inventory: wire.inventory,
            layout: wire.layout,
            capabilities: wire.capabilities,
        };
        value.validate().map_err(deserialize_error)?;
        Ok(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CardinalRelation {
    Left,
    Right,
    Above,
    Below,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UiCommand {
    RefreshDiagnostics,
    StartDiscovery,
    StopDiscovery,
    SelectCandidate {
        handle: CandidateHandle,
    },
    BeginBootstrap,
    ConfirmBootstrap {
        matches: bool,
    },
    SelectRelationship {
        relationship: RelationshipHandle,
    },
    BeginV01,
    ConfirmV01 {
        matches: bool,
    },
    RefreshInventory,
    MoveDisplay {
        display: DisplayHandle,
        relation: CardinalRelation,
        alignment: i32,
    },
    ResetLayout,
    SubmitLayout,
    RespondLayout {
        accept: bool,
    },
    Cancel,
    ForgetRelationship {
        relationship: RelationshipHandle,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum UiCommandWire {
    RefreshDiagnostics,
    StartDiscovery,
    StopDiscovery,
    SelectCandidate {
        handle: CandidateHandle,
    },
    BeginBootstrap,
    ConfirmBootstrap {
        matches: bool,
    },
    SelectRelationship {
        relationship: RelationshipHandle,
    },
    BeginV01,
    ConfirmV01 {
        matches: bool,
    },
    RefreshInventory,
    MoveDisplay {
        display: DisplayHandle,
        relation: CardinalRelation,
        alignment: i32,
    },
    ResetLayout,
    SubmitLayout,
    RespondLayout {
        accept: bool,
    },
    Cancel,
    ForgetRelationship {
        relationship: RelationshipHandle,
    },
}

impl From<UiCommandWire> for UiCommand {
    fn from(value: UiCommandWire) -> Self {
        match value {
            UiCommandWire::RefreshDiagnostics => Self::RefreshDiagnostics,
            UiCommandWire::StartDiscovery => Self::StartDiscovery,
            UiCommandWire::StopDiscovery => Self::StopDiscovery,
            UiCommandWire::SelectCandidate { handle } => Self::SelectCandidate { handle },
            UiCommandWire::BeginBootstrap => Self::BeginBootstrap,
            UiCommandWire::ConfirmBootstrap { matches } => Self::ConfirmBootstrap { matches },
            UiCommandWire::SelectRelationship { relationship } => {
                Self::SelectRelationship { relationship }
            }
            UiCommandWire::BeginV01 => Self::BeginV01,
            UiCommandWire::ConfirmV01 { matches } => Self::ConfirmV01 { matches },
            UiCommandWire::RefreshInventory => Self::RefreshInventory,
            UiCommandWire::MoveDisplay {
                display,
                relation,
                alignment,
            } => Self::MoveDisplay {
                display,
                relation,
                alignment,
            },
            UiCommandWire::ResetLayout => Self::ResetLayout,
            UiCommandWire::SubmitLayout => Self::SubmitLayout,
            UiCommandWire::RespondLayout { accept } => Self::RespondLayout { accept },
            UiCommandWire::Cancel => Self::Cancel,
            UiCommandWire::ForgetRelationship { relationship } => {
                Self::ForgetRelationship { relationship }
            }
        }
    }
}

fn strict_command_shape(value: &Value) -> Result<(), UiContractError> {
    let object = value.as_object().ok_or(UiContractError::InvalidCommand)?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or(UiContractError::InvalidCommand)?;
    let allowed = match kind {
        "refresh_diagnostics"
        | "start_discovery"
        | "stop_discovery"
        | "begin_bootstrap"
        | "begin_v01"
        | "refresh_inventory"
        | "reset_layout"
        | "submit_layout"
        | "cancel" => ["kind"].as_slice(),
        "select_candidate" => ["kind", "handle"].as_slice(),
        "confirm_bootstrap" | "confirm_v01" => ["kind", "matches"].as_slice(),
        "select_relationship" | "forget_relationship" => ["kind", "relationship"].as_slice(),
        "move_display" => ["kind", "display", "relation", "alignment"].as_slice(),
        "respond_layout" => ["kind", "accept"].as_slice(),
        _ => return Err(UiContractError::InvalidCommand),
    };
    if object.keys().all(|key| allowed.contains(&key.as_str())) {
        Ok(())
    } else {
        Err(UiContractError::InvalidCommand)
    }
}

impl<'de> Deserialize<'de> for UiCommand {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        strict_command_shape(&value).map_err(deserialize_error)?;
        let command: UiCommand = serde_json::from_value::<UiCommandWire>(value)
            .map(Into::into)
            .map_err(|_| deserialize_error(UiContractError::InvalidCommand))?;
        command.validate().map_err(deserialize_error)?;
        Ok(command)
    }
}

impl UiCommand {
    pub fn validate(&self) -> Result<(), UiContractError> {
        if let Self::MoveDisplay { alignment, .. } = self
            && !(-MAX_ALIGNMENT..=MAX_ALIGNMENT).contains(alignment)
        {
            return Err(UiContractError::InvalidAlignment);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UiError {
    InvalidState,
    InvalidCommand,
    InvalidRequest,
    RequestIdConflict,
    RequestLimit,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UiRequest {
    pub schema_version: u16,
    pub id: RequestId,
    pub command: UiCommand,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UiRequestWire {
    schema_version: u16,
    id: RequestId,
    command: UiCommand,
}

impl UiRequest {
    pub fn new(id: RequestId, command: UiCommand) -> Result<Self, UiContractError> {
        let value = Self {
            schema_version: UI_SCHEMA_VERSION,
            id,
            command,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), UiContractError> {
        if self.schema_version != UI_SCHEMA_VERSION {
            return Err(UiContractError::UnsupportedSchema);
        }
        self.command.validate()
    }

    pub fn as_control_request(&self) -> Result<control_api::Request, UiContractError> {
        self.validate()?;
        control_api::typed_request(self.id.as_str(), "ui.command", &self.command)
            .map_err(|_| UiContractError::ControlFrame)
    }
}

impl<'de> Deserialize<'de> for UiRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = UiRequestWire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            id: wire.id,
            command: wire.command,
        };
        value.validate().map_err(deserialize_error)?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum UiResponse {
    Snapshot(UiSnapshot),
    Acknowledged,
    Error(UiError),
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum UiResponseWire {
    Snapshot(UiSnapshot),
    Acknowledged,
    Error(UiError),
}

impl From<UiResponseWire> for UiResponse {
    fn from(value: UiResponseWire) -> Self {
        match value {
            UiResponseWire::Snapshot(snapshot) => Self::Snapshot(snapshot),
            UiResponseWire::Acknowledged => Self::Acknowledged,
            UiResponseWire::Error(error) => Self::Error(error),
        }
    }
}

fn strict_response_shape(value: &Value) -> Result<(), UiContractError> {
    let object = value.as_object().ok_or(UiContractError::InvalidCommand)?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or(UiContractError::InvalidCommand)?;
    let allowed = match kind {
        "acknowledged" => ["kind"].as_slice(),
        "snapshot" | "error" => ["kind", "value"].as_slice(),
        _ => return Err(UiContractError::InvalidCommand),
    };
    if object.keys().all(|key| allowed.contains(&key.as_str())) {
        Ok(())
    } else {
        Err(UiContractError::InvalidCommand)
    }
}

impl<'de> Deserialize<'de> for UiResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        strict_response_shape(&value).map_err(deserialize_error)?;
        let response: UiResponse = serde_json::from_value::<UiResponseWire>(value)
            .map(Into::into)
            .map_err(|_| deserialize_error(UiContractError::InvalidCommand))?;
        response.validate().map_err(deserialize_error)?;
        Ok(response)
    }
}

impl UiResponse {
    fn validate(&self) -> Result<(), UiContractError> {
        if let Self::Snapshot(snapshot) = self {
            snapshot.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum UiEvent {
    SnapshotPublished { generation: u64 },
    DiagnosticsRefreshed { generation: u64 },
    CommandRejected { id: RequestId, error: UiError },
}

#[derive(Debug, Default)]
pub struct UiRequestCache {
    requests: BTreeMap<RequestId, (UiRequest, UiResponse)>,
}

impl UiRequestCache {
    pub fn record(
        &mut self,
        request: UiRequest,
        response: UiResponse,
    ) -> Result<UiResponse, UiContractError> {
        request.validate()?;
        response.validate()?;
        if let Some((previous, prior_response)) = self.requests.get(&request.id) {
            return if previous == &request {
                Ok(prior_response.clone())
            } else {
                Err(UiContractError::RequestIdConflict)
            };
        }
        if self.requests.len() >= MAX_REPLAYED_REQUESTS {
            return Err(UiContractError::RequestLimit);
        }
        self.requests
            .insert(request.id.clone(), (request, response.clone()));
        Ok(response)
    }
}
