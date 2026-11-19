"""Central registry for PENTURION security agents."""

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True)
class AgentDefinition:
    """Metadata describing a PENTURION security agent."""

    agent_id: str
    name: str
    description: str

    dependencies: tuple[str, ...]

    input_types: tuple[str, ...]
    output_types: tuple[str, ...]

    network_access: bool
    requires_scope_validation: bool

    retry_safe: bool
    timeout_seconds: int

    enabled: bool = False


_AGENT_DEFINITIONS = (
    AgentDefinition(
        agent_id="A01",
        name="Subdomain Discovery",
        description="Discover subdomains using passive reconnaissance.",
        dependencies=(),
        input_types=("root_domain",),
        output_types=("subdomains",),
        network_access=True,
        requires_scope_validation=True,
        retry_safe=True,
        timeout_seconds=120,
    ),
    AgentDefinition(
        agent_id="A02",
        name="DNS Enumeration",
        description="Collect DNS records and identify DNS configuration issues.",
        dependencies=("A01",),
        input_types=("root_domain", "subdomains"),
        output_types=("dns_records",),
        network_access=True,
        requires_scope_validation=True,
        retry_safe=True,
        timeout_seconds=60,
    ),
    AgentDefinition(
        agent_id="A03",
        name="Live Host Discovery",
        description="Identify reachable web hosts.",
        dependencies=("A01", "A02"),
        input_types=("subdomains", "dns_records"),
        output_types=("live_hosts", "http_services"),
        network_access=True,
        requires_scope_validation=True,
        retry_safe=True,
        timeout_seconds=120,
    ),
    AgentDefinition(
        agent_id="A04",
        name="Port Scanning",
        description="Identify open ports and services on authorized hosts.",
        dependencies=("A03",),
        input_types=("live_hosts",),
        output_types=("open_ports", "services"),
        network_access=True,
        requires_scope_validation=True,
        retry_safe=False,
        timeout_seconds=180,
    ),
    AgentDefinition(
        agent_id="A05",
        name="Web Crawling",
        description="Discover application URLs and endpoints.",
        dependencies=("A03",),
        input_types=("live_hosts",),
        output_types=("urls", "endpoints"),
        network_access=True,
        requires_scope_validation=True,
        retry_safe=False,
        timeout_seconds=180,
    ),
    AgentDefinition(
        agent_id="A06",
        name="Technology Fingerprinting",
        description="Identify web frameworks, servers, CMS, and technologies.",
        dependencies=("A03",),
        input_types=("live_hosts",),
        output_types=("technologies",),
        network_access=True,
        requires_scope_validation=True,
        retry_safe=True,
        timeout_seconds=60,
    ),
    AgentDefinition(
        agent_id="A07",
        name="Directory Discovery",
        description="Discover directories and application paths.",
        dependencies=("A03",),
        input_types=("live_hosts",),
        output_types=("directories",),
        network_access=True,
        requires_scope_validation=True,
        retry_safe=False,
        timeout_seconds=180,
    ),
    AgentDefinition(
        agent_id="A08",
        name="Sensitive File Discovery",
        description="Identify exposed backups, configuration files, and documents.",
        dependencies=("A05", "A07"),
        input_types=("urls", "directories"),
        output_types=("sensitive_files",),
        network_access=True,
        requires_scope_validation=True,
        retry_safe=False,
        timeout_seconds=120,
    ),
    AgentDefinition(
        agent_id="A09",
        name="JavaScript Discovery",
        description="Discover and inventory JavaScript assets.",
        dependencies=("A05",),
        input_types=("urls",),
        output_types=("javascript_assets",),
        network_access=True,
        requires_scope_validation=True,
        retry_safe=True,
        timeout_seconds=120,
    ),
    AgentDefinition(
        agent_id="A10",
        name="Secret and Credential Analysis",
        description="Analyze authorized JavaScript assets for exposed secrets.",
        dependencies=("A09",),
        input_types=("javascript_assets",),
        output_types=("secret_candidates",),
        network_access=False,
        requires_scope_validation=True,
        retry_safe=True,
        timeout_seconds=120,
    ),
    AgentDefinition(
        agent_id="A11",
        name="Security Headers Analysis",
        description="Analyze HTTP security response headers.",
        dependencies=("A03",),
        input_types=("live_hosts",),
        output_types=("header_findings",),
        network_access=True,
        requires_scope_validation=True,
        retry_safe=True,
        timeout_seconds=30,
    ),
    AgentDefinition(
        agent_id="A12",
        name="TLS Configuration Analysis",
        description="Analyze TLS configuration and certificate properties.",
        dependencies=("A03",),
        input_types=("live_hosts",),
        output_types=("tls_findings",),
        network_access=True,
        requires_scope_validation=True,
        retry_safe=True,
        timeout_seconds=60,
    ),
    AgentDefinition(
        agent_id="A13",
        name="CVE and Known Vulnerability Detection",
        description="Identify potentially vulnerable technologies and services.",
        dependencies=("A04", "A06"),
        input_types=("services", "technologies"),
        output_types=("vulnerability_candidates",),
        network_access=False,
        requires_scope_validation=True,
        retry_safe=True,
        timeout_seconds=120,
    ),
    AgentDefinition(
        agent_id="A14",
        name="Information Disclosure Analysis",
        description="Identify exposed information and sensitive error messages.",
        dependencies=("A03", "A05"),
        input_types=("live_hosts", "urls"),
        output_types=("disclosure_findings",),
        network_access=True,
        requires_scope_validation=True,
        retry_safe=False,
        timeout_seconds=120,
    ),
    AgentDefinition(
        agent_id="A15",
        name="Cookie Security Analysis",
        description="Analyze cookie security attributes.",
        dependencies=("A03", "A05"),
        input_types=("live_hosts", "urls"),
        output_types=("cookie_findings",),
        network_access=True,
        requires_scope_validation=True,
        retry_safe=True,
        timeout_seconds=60,
    ),
    AgentDefinition(
        agent_id="A16",
        name="HTTP Method Analysis",
        description="Analyze supported HTTP methods.",
        dependencies=("A03",),
        input_types=("live_hosts",),
        output_types=("http_method_findings",),
        network_access=True,
        requires_scope_validation=True,
        retry_safe=False,
        timeout_seconds=30,
    ),
)


def _build_registry() -> Mapping[str, AgentDefinition]:
    """Build an immutable registry and validate its basic structure."""

    registry: dict[str, AgentDefinition] = {}

    for agent in _AGENT_DEFINITIONS:
        if agent.agent_id in registry:
            raise ValueError(
                f"Duplicate agent ID: {agent.agent_id}"
            )

        if agent.timeout_seconds <= 0:
            raise ValueError(
                f"Invalid timeout for {agent.agent_id}"
            )

        if len(agent.dependencies) != len(set(agent.dependencies)):
            raise ValueError(
                f"Duplicate dependencies for {agent.agent_id}"
            )

        if agent.agent_id in agent.dependencies:
            raise ValueError(
                f"Agent cannot depend on itself: {agent.agent_id}"
            )

        registry[agent.agent_id] = agent

    for agent in registry.values():
        for dependency in agent.dependencies:
            if dependency not in registry:
                raise ValueError(
                    f"{agent.agent_id} references unknown dependency "
                    f"{dependency}"
                )

    return MappingProxyType(registry)


AGENT_REGISTRY = _build_registry()


def get_agent(agent_id: str) -> AgentDefinition:
    """Retrieve an agent definition by ID."""

    try:
        return AGENT_REGISTRY[agent_id]
    except KeyError:
        raise KeyError(
            f"Unknown PENTURION agent: {agent_id}"
        ) from None


def get_all_agents() -> tuple[AgentDefinition, ...]:
    """Return all registered agents."""

    return tuple(AGENT_REGISTRY.values())


def get_enabled_agents() -> tuple[AgentDefinition, ...]:
    """Return agents currently permitted to execute."""

    return tuple(
        agent
        for agent in AGENT_REGISTRY.values()
        if agent.enabled
    )