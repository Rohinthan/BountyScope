// Simulated client bundle containing candidate API routes
const API_ROUTES = {
    users: "/api/v1/users",
    telemetry: "/api/v2/metrics",
    graphql: "/graphql",
    aiGateway: "/v1/models"
};

function fetchProfile() {
    return fetch("/api/v1/profile");
}
