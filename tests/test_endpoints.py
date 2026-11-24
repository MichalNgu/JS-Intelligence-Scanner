from core.models import JavaScriptResource
from modules.endpoint_finder import EndpointFinder


def test_extracts_admin_graphql_and_websocket():
    content = '''
    fetch("/api/v1/users");
    axios.get("/api/v1/admin");
    const socket = new WebSocket("wss://example.com/socket");
    const query = "/graphql";
    '''
    resource = JavaScriptResource(
        url="https://example.com/app.js",
        source_url="https://example.com/",
        content=content,
    )
    findings = EndpointFinder().analyze([resource])
    values = {finding.value for finding in findings}
    assert "/api/v1/users" in values
    assert "/api/v1/admin" in values
    assert "/graphql" in values
    assert "wss://example.com/socket" in values
