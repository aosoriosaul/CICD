
// Establece valores de trazabilidad
context.setVariable('flow.trazabilidad.request.id', obtenerIdTrazabilidad());
context.setVariable('flow.trazabilidad.ip', obtenerIP());

function obtenerIdTrazabilidad() {
    if (context.getVariable('request.header.x-request-id') !== null) {
        return context.getVariable('request.header.x-request-id');
    } else {
        return context.getVariable('messageid');
    }
}

function obtenerIP() {
    return context.getVariable('request.header.X-Forwarded-For');
}