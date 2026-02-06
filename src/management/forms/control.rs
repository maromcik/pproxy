use serde::Deserialize;

#[derive(Deserialize)]
pub struct ControlParams {
    #[serde(default)]
    pub action: Option<String>,
}
