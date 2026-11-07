use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ProfileConfig {
    #[serde(rename = "@version")]
    pub version: Option<String>,
    #[serde(rename = "ProxyList")]
    pub proxy_list: Option<ProxyList>,
    #[serde(rename = "RuleList")]
    pub rule_list: Option<RuleList>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyList {
    #[serde(rename = "Proxy", default)]
    pub proxies: Vec<ProxyItem>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyItem {
    #[serde(rename = "@id")]
    pub id: u32,
    #[serde(rename = "@type")]
    pub proxy_type: String,
    #[serde(rename = "Address")]
    pub address: String,
    #[serde(rename = "Port")]
    pub port: u16,
    #[serde(rename = "Options")]
    pub options: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RuleList {
    #[serde(rename = "Rule", default)]
    pub rules: Vec<RuleItem>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RuleItem {
    #[serde(rename = "@enabled")]
    pub enabled: Option<bool>,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Applications")]
    pub applications: Option<String>,
    #[serde(rename = "Targets")]
    pub targets: Option<String>,
    #[serde(rename = "Ports")]
    pub ports: Option<String>,
    #[serde(rename = "Action")]
    pub action: RuleActionItem,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RuleActionItem {
    #[serde(rename = "@type")]
    pub action_type: String,
    #[serde(rename = "$value")]
    pub value: Option<u32>,
}

impl ProfileConfig {
    pub fn from_xml(xml_content: &str) -> Result<Self, quick_xml::DeError> {
        quick_xml::de::from_str(xml_content)
    }
}
