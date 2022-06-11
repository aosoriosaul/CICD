Feature: /aclaraciones POST
    Obtener Informacion de Aclaraciones de cargos no reconocidos

    Scenario: Negocio un consumer key y secret key de la app de prueba
        Given I have basic authentication credentials `apigeeUsername` and `apigeePassword`
        And I have valid client TLS configuration
        When I GET `apigeeHost`/v1/organizations/`apigeeOrg`/developers/`apigeeDeveloper`/apps/`apigeeApp`
        Then response code should be 200
        And response body should be valid json
        And I store the value of body path $.credentials[0].consumerKey as globalConsumerKey in global scope
        And I store the value of body path $.credentials[0].consumerSecret as globalConsumerSecret in global scope

    Scenario: Negocia un access token con el Authorization server

        Given I set form parameters to
        | parameter  | value              |
        | grant_type | client_credentials |

        And I have basic authentication credentials `globalConsumerKey` and `globalConsumerSecret`
        And I have valid client TLS configuration
        When I POST to `apigeeDomain`/`apigeeOauthEndpoint`

        Then response code should be 200
        And response body should be valid json
        And I store the value of body path $.access_token as access token


    Scenario: Obtencion de llaves asimétricas
        Given I set bearer token
        And I have valid client TLS configuration
        And I set x-ismock header to true
        When  I GET `apigeeDomain`/operaciones-baz/seguridad/v1/aplicaciones/llaves
        Then response code should be 200
        And response body should be valid json
        And response body path $.mensaje should be ^([A-Za-zá-úÁ-Ú0-9\s,.-])+$
        And response body path $.folio should be ^[a-z0-9-]{1,}$
        And response body path $.resultado.idAcceso should be ^[a-zA-Z0-9]{1,60}$
        And I store the value of body path $.resultado.idAcceso as idAccess in global scope
        And I store the deciphering value encrypted with AES of body path $.resultado.accesoPublico as publicKey in global scope
        And I store the deciphering value encrypted with AES of body path $.resultado.accesoPrivado as privateKey in global scope
        And I store the deciphering value encrypted with AES of body path $.resultado.accesoSimetrico as accessSymmetric in global scope
        And I store the deciphering value encrypted with AES of body path $.resultado.codigoAutentificacionHash as codeHash in global scope

    Scenario Outline: /aclaraciones 200 ok
        Given I set bearer token
        And I set Content-Type header to application/json
        And I have valid client TLS configuration
        And I set x-ismock header to true
        And I set x-id-acceso header to `idAccess`
        And I set x-ip-origen header to <ipOrigen>
        And I need to encrypt with RSA as algorithm the parameters {aclaracion[*].numeroTarjeta,aclaracion[*].numeroCuenta,aclaracion[*].montoTotal,cliente[*].id,cliente[*].idClienteBanco,movimientos[*].numeroOperacion,movimientos[*].numeroAutorizacion,movimientos[*].monto,movimientos[*].montoReclamo,operador[*].numeroEmpleado,operador[*].perfil}
        And I set body to <body>
        When I POST to `apigeeDomain`/operaciones-baz/plataforma-aclaraciones/administracion-aclaraciones/`deploymentSuffix`/aclaraciones
        Then response code should be 200
        And response body should be valid json
        And response body path $.mensaje should be ^Operaci(o|ó)n (e|E)xitosa(.|)$
        And response body path $.folio should be ^[a-zA-Z0-9,-]+$
        And response body path $.resultado.folioAclaracion should be ^[0-9]+$

    Examples:
        |body                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
        |{"idCanal":2,"idOrigen":1,"producto":"TARJETA DEBITO","subProducto":"GUARDADITO KIDS","aclaracion":{"idTipo":485,"numeroTarjeta":"4409102650193056","numeroCuenta":"Ksfus9Zn5Gsv8ifeEbI9HA5wuQac","numeroMovimientos":1,"comentario":"Me realizaron el cargo y no fui al comercio","montoTotal":"500.00","recursoPago":0,"observacion":"No coincide la hora del movimiento","conceptoBancaDigital":"Compra con tarjeta movimiento pendiente","documentos":[{"idTipo":"1","uri":"01-100-002"}]},"cliente":{"id":"12345","idClienteBanco":"456678","idEstatusCuenta":1,"idEstatusTarjeta":0},"movimientos":[{"idTipo":1,"idEstatus":1,"numeroOperacion":"123","numeroAutorizacion":"1234","concepto":"PAGO EN COMERICIO","descripcion":"Pago de comida en Mercado gastronomico","fecha":"25/09/2019","hora":"16:40:45","monto":"400.00","montoReclamo":"1525.52","codigoDivisa":"MXP","comercio":{"numeroAfiliacion":123456,"giro":6011},"documentos":[{"idTipo":"1","uri":"01-100-002"}]}],"operador":{"numeroEmpleado":"782732","idSucursalSolicitud":"0172","perfil":"Ejecutivo"}}|
        #|{"idCanal":2,"idOrigen":1,"producto":"TARJETA DEBITO","subProducto":"GUARDADITO KIDS","aclaracion":{"idTipo":485,"numeroTarjeta":"M9Zn5Gsv8ifeEbI9HA5wuQ","numeroCuenta":"Ksfus9Zn5Gsv8ifeEbI9HA5wuQac","numeroMovimientos":1,"comentario":"Me realizaron el cargo y no fui al comercio","montoTotal":500,"recursoPago":0,"observacion":"No coincide la hora del movimiento","conceptoBancaDigital":"Compra con tarjeta movimiento pendiente","documentos":[{"uri":"01-100-002","idTipo":"1"}]},"cliente":{"id":"12345","idClienteBanco":456678,"idEstatusCuenta":1,"idEstatusTarjeta":0},"movimientos":[{"idTipo":1,"idEstatus":1,"numeroOperacion":123,"numeroAutorizacion":1234,"concepto":"PAGO EN COMERICIO","descripcion":"Pago de comida en Mercado gastronomico","fecha":"25/09/2019","hora":"16:40:45","monto":"400.00","montoReclamo":1525.52,"codigoDivisa":"MXP","comercio":{"numeroAfiliacion":123456,"giro":6011,"comercio":"AMAZON MX, MEXICO DF","canalOperacion":"E-COMMERCE","adquirente":"AMAZON"},"documentos":[{"uri":"01-100-002","idTipo":"1"}]}],"operador":{"numeroEmpleado":"782732","idSucursalSolicitud":"0172","perfil":"Ejecutivo"}}|


    Scenario Outline:  /aclaraciones 400 bad request.

        Given I set bearer token
        And I set Content-Type header to application/json
        And I have valid client TLS configuration
        And I set x-ismock header to true
        And I set x-id-acceso header to `idAccess`
        And I set x-ip-origen header to <ipOrigen>
        And I set body to <body>
        When I POST to `apigeeDomain`/operaciones-baz/plataforma-aclaraciones/administracion-aclaraciones/`deploymentSuffix`/aclaraciones
        Then response code should be 400
        And response body should be valid json

        And response body path $.codigo should be ^400.Operaciones-Baz-Plataforma-Aclaraciones-Gestion-Aclaraciones.\d{4}$
        And response body path $.mensaje should be ^[A-Za-záéíóúÁÉÍÓÚ0-9.,-\s:]{1,255}$
        And response body path $.folio should be [a-zA-Z0-9\W]{1,}
        And response body path $.info should be ^https:\/\/baz-developer\.bancoazteca\.com\.mx\/\w{4,6}#400\.Operaciones-Baz-Plataforma-Aclaraciones-Gestion-Aclaraciones.\d{0,}|[A-Z]{0,}\d{0,}$
        And response body path $.detalles[*] should be ^[A-Za-záéíóúÁÉÍÓÚ0-9.,-\s:]{1,255}$

    Examples:
        |body                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
        |{"idCanal":null,"idOrigen":1,"producto":"TARJETA DEBITO","subProducto":"GUARDADITO KIDS","aclaracion":{"idTipo":485,"numeroTarjeta":"4409102650193056","numeroCuenta":"Ksfus9Zn5Gsv8ifeEbI9HA5wuQac","numeroMovimientos":1,"comentario":"Me realizaron el cargo y no fui al comercio","montoTotal":"500.00","recursoPago":0,"observacion":"No coincide la hora del movimiento","conceptoBancaDigital":"Compra con tarjeta movimiento pendiente","documentos":[{"idTipo":"1","uri":"01-100-002"}]},"cliente":{"id":"12345","idClienteBanco":"456678","idEstatusCuenta":1,"idEstatusTarjeta":0},"movimientos":[{"idTipo":1,"idEstatus":1,"numeroOperacion":"123","numeroAutorizacion":"1234","concepto":"PAGO EN COMERICIO","descripcion":"Pago de comida en Mercado gastronomico","fecha":"25/09/2019","hora":"16:40:45","monto":"400.00","montoReclamo":"1525.52","codigoDivisa":"MXP","comercio":{"numeroAfiliacion":123456,"giro":6011},"documentos":[{"idTipo":"1","uri":"01-100-002"}]}],"operador":{"numeroEmpleado":"782732","idSucursalSolicitud":"0172","perfil":"Ejecutivo"}}|

    Scenario Outline:  /aclaraciones 401 bad request.

        Given I set bearer token
        And I set Content-Type header to application/json
        And I have valid client TLS configuration
        And I set x-ismock header to true
        And I set x-id-acceso header to `idAccess`
        And I set x-ip-origen header to <ipOrigen>
        And I set body to <body>
        When I POST to `apigeeDomain`/operaciones-baz/plataforma-aclaraciones/administracion-aclaraciones/`deploymentSuffix`/aclaraciones
        Then response code should be 401
        And response body should be valid json

        And response body path $.codigo should be ^401.Operaciones-Baz-Plataforma-Aclaraciones-Gestion-Aclaraciones.\d{4}$
        And response body path $.mensaje should be ^[A-Za-záéíóúÁÉÍÓÚ0-9.,-\s:]{1,255}$
        And response body path $.folio should be [a-zA-Z0-9\W]{1,}
        And response body path $.info should be ^https:\/\/baz-developer\.bancoazteca\.com\.mx\/\w{4,6}#401\.Operaciones-Baz-Plataforma-Aclaraciones-Gestion-Aclaraciones.\d{0,}|[A-Z]{0,}\d{0,}$
        And response body path $.detalles[*] should be ^[A-Za-záéíóúÁÉÍÓÚ0-9.,-\s:]{1,255}$

    Examples:
        |body                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
        |{"idCanal":2,"idOrigen":0,"producto":"TARJETA DEBITO","subProducto":"GUARDADITO KIDS","aclaracion":{"idTipo":485,"numeroTarjeta":"M9Zn5Gsv8ifeEbI9HA5wuQ","numeroCuenta":"Ksfus9Zn5Gsv8ifeEbI9HA5wuQac","numeroMovimientos":1,"comentario":"Me realizaron el cargo y no fui al comercio","montoTotal":"500.00","recursoPago":0,"observacion":"No coincide la hora del movimiento","conceptoBancaDigital":"Compra con tarjeta movimiento pendiente","documentos":[{"idTipo":"1","uri":"01-100-002"}]},"cliente":{"id":"12345","idClienteBanco":"456678","idEstatusCuenta":1,"idEstatusTarjeta":0},"movimientos":[{"idTipo":1,"idEstatus":1,"numeroOperacion":"123","numeroAutorizacion":"1234","concepto":"PAGO EN COMERICIO","descripcion":"Pago de comida en Mercado gastronomico","fecha":"25/09/2019","hora":"16:40:45","monto":"400.00","montoReclamo":"1525.52","codigoDivisa":"MXP","comercio":{"numeroAfiliacion":123456,"giro":6011},"documentos":[{"idTipo":"1","uri":"01-100-002"}]}],"operador":{"numeroEmpleado":"782732","idSucursalSolicitud":"0172","perfil":"Ejecutivo"}}|

    Scenario Outline:  /aclaraciones 404 not found.

        Given I set bearer token
        And I set Content-Type header to application/json
        And I have valid client TLS configuration
        And I set x-ismock header to true
        And I set x-id-acceso header to `idAccess`
        And I set x-ip-origen header to <ipOrigen>
        And I set body to <body>
        When I POST to `apigeeDomain`/operaciones-baz/plataforma-aclaraciones/administracion-aclaraciones/`deploymentSuffix`/aclaraciones
        Then response code should be 404
        And response body should be valid json

        And response body path $.codigo should be ^404.Operaciones-Baz-Plataforma-Aclaraciones-Gestion-Aclaraciones.\d{4}$
        And response body path $.mensaje should be ^[A-Za-záéíóúÁÉÍÓÚ0-9.,-\s:]{1,255}$
        And response body path $.folio should be [a-zA-Z0-9\W]{1,}
        And response body path $.info should be ^https:\/\/baz-developer\.bancoazteca\.com\.mx\/\w{4,6}#404\.Operaciones-Baz-Plataforma-Aclaraciones-Gestion-Aclaraciones.\d{0,}|[A-Z]{0,}\d{0,}$
        And response body path $.detalles[*] should be ^[A-Za-záéíóúÁÉÍÓÚ0-9.,-\s:]{1,255}$

    Examples:
        |body                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
        |{"idCanal":"nf","idOrigen":1,"producto":"TARJETA DEBITO","subProducto":"GUARDADITO KIDS","aclaracion":{"idTipo":485,"numeroTarjeta":"M9Zn5Gsv8ifeEbI9HA5wuQ","numeroCuenta":"Ksfus9Zn5Gsv8ifeEbI9HA5wuQac","numeroMovimientos":1,"comentario":"Me realizaron el cargo y no fui al comercio","montoTotal":"500.00","recursoPago":0,"observacion":"No coincide la hora del movimiento","conceptoBancaDigital":"Compra con tarjeta movimiento pendiente","documentos":[{"idTipo":"1","uri":"01-100-002"}]},"cliente":{"id":"12345","idClienteBanco":"456678","idEstatusCuenta":1,"idEstatusTarjeta":0},"movimientos":[{"idTipo":1,"idEstatus":1,"numeroOperacion":"123","numeroAutorizacion":"1234","concepto":"PAGO EN COMERICIO","descripcion":"Pago de comida en Mercado gastronomico","fecha":"25/09/2019","hora":"16:40:45","monto":"400.00","montoReclamo":"1525.52","codigoDivisa":"MXP","comercio":{"numeroAfiliacion":123456,"giro":6011},"documentos":[{"idTipo":"1","uri":"01-100-002"}]}],"operador":{"numeroEmpleado":"782732","idSucursalSolicitud":"0172","perfil":"Ejecutivo"}}|

    Scenario Outline:  /aclaraciones 500 internal server error.

        Given I set bearer token
        And I set Content-Type header to application/json
        And I have valid client TLS configuration
        And I set x-ismock header to true
        And I set x-id-acceso header to `idAccess`
        And I set x-ip-origen header to <ipOrigen>
        And I set body to <body>
        When I POST to `apigeeDomain`/operaciones-baz/plataforma-aclaraciones/administracion-aclaraciones/`deploymentSuffix`/aclaraciones

        Then response code should be 500
        And response body should be valid json

        And response body path $.codigo should be ^500.Operaciones-Baz-Plataforma-Aclaraciones-Gestion-Aclaraciones.\d{4}$
        And response body path $.mensaje should be ^[A-Za-záéíóúÁÉÍÓÚ0-9.,-\s:]{1,255}$
        And response body path $.folio should be [a-zA-Z0-9\W]{1,}
        And response body path $.info should be ^https:\/\/baz-developer\.bancoazteca\.com\.mx\/\w{4,6}#500\.Operaciones-Baz-Plataforma-Aclaraciones-Gestion-Aclaraciones.\d{0,}|[A-Z]{0,}\d{0,}$
        And response body path $.detalles[*] should be ^[A-Za-záéíóúÁÉÍÓÚ0-9.,-\s:]{1,255}$

    Examples:
        |body                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
        |{"idCanal":"bad","idOrigen":1,"producto":"TARJETA DEBITO","subProducto":"GUARDADITO KIDS","aclaracion":{"idTipo":485,"numeroTarjeta":"M9Zn5Gsv8ifeEbI9HA5wuQ","numeroCuenta":"Ksfus9Zn5Gsv8ifeEbI9HA5wuQac","numeroMovimientos":1,"comentario":"Me realizaron el cargo y no fui al comercio","montoTotal":"500.00","recursoPago":0,"observacion":"No coincide la hora del movimiento","conceptoBancaDigital":"Compra con tarjeta movimiento pendiente","documentos":[{"idTipo":"1","uri":"01-100-002"}]},"cliente":{"id":"12345","idClienteBanco":"456678","idEstatusCuenta":1,"idEstatusTarjeta":0},"movimientos":[{"idTipo":1,"idEstatus":1,"numeroOperacion":"123","numeroAutorizacion":"1234","concepto":"PAGO EN COMERICIO","descripcion":"Pago de comida en Mercado gastronomico","fecha":"25/09/2019","hora":"16:40:45","monto":"400.00","montoReclamo":"1525.52","codigoDivisa":"MXP","comercio":{"numeroAfiliacion":123456,"giro":6011},"documentos":[{"idTipo":"1","uri":"01-100-002"}]}],"operador":{"numeroEmpleado":"782732","idSucursalSolicitud":"0172","perfil":"Ejecutivo"}}|