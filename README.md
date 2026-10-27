# # Base de seguridad de la cuenta: CloudTrail, AWS Config y remediación automática

## Objetivo
Que la cuenta de AWS se vigile sola y corrija ciertos errores sin intervención manual. Si alguien crea un bucket de S3 que acepta conexiones sin HTTPS, el sistema lo detecta, lo corrige y avisa por email.

## Arquitectura
- **CloudTrail:** registra la actividad de la cuenta y la guarda en un bucket de S3 privado, con validación de integridad de los archivos.
- **AWS Config:** registra únicamente los buckets de S3 (para mantener el costo bajo) y evalúa la regla administrada `s3-ssl-requests-only`, que exige que cada bucket rechace conexiones sin HTTPS.
- **EventBridge:** cuando Config marca un bucket como no conforme, dispara la función Lambda.
- **Lambda (Python 3.13):** agrega al bucket una política que deniega las conexiones sin HTTPS (`aws:SecureTransport = false`) y avisa por SNS.
- **SNS:** envía los avisos por email.
- **IAM:** la Lambda solo puede leer y escribir la política de los buckets cuyo nombre empieza con `prueba-seguridad-`, publicar en el tema de SNS y escribir sus logs.

Toda la infraestructura está definida con **Terraform** en la región `us-east-1`. Los buckets de logs son privados, con el acceso público bloqueado y HTTPS obligatorio.

## Decisión de diseño: remediación acotada
La corrección automática solo se aplica a buckets con el prefijo `prueba-seguridad-`, y los permisos de IAM de la Lambda están limitados a ese prefijo. Para cualquier otro bucket, la Lambda **solo avisa** y no modifica nada. Así evito que una automatización rompa por accidente un recurso que sirve un sitio o una aplicación.

## Cómo funciona
1. Config evalúa los buckets de S3 con la regla `s3-ssl-requests-only`.
2. Si un bucket no cumple, Config emite un evento de cambio de cumplimiento.
3. EventBridge lo recibe y ejecuta la Lambda.
4. Si el bucket está dentro del alcance, la Lambda le agrega la política `DenyInsecureTransport` y envía un email. Si está fuera del alcance, solo envía el aviso.
5. Config vuelve a evaluar y el bucket pasa a conforme.

## Cómo usarlo
Crear un archivo `terraform.tfvars` con el email que recibirá los avisos (no se sube al repositorio):

```hcl
email = "tu-email@ejemplo.com"
```

Desplegar y confirmar la suscripción de SNS desde el correo que llega:

```bash
terraform init
terraform plan
terraform apply
```

Probar la remediación creando un bucket dentro del alcance:

```bash
aws s3 mb s3://prueba-seguridad-XXXX --region us-east-1
aws s3api get-bucket-policy --bucket prueba-seguridad-XXXX --region us-east-1
```

Unos minutos después, el bucket tiene la política `DenyInsecureTransport` que no existía al crearlo. Para eliminar todo:

```bash
aws s3 rb s3://prueba-seguridad-XXXX --force --region us-east-1
terraform destroy
```

## Resultados


### La regla de Config detecta los buckets sin HTTPS obligatorio
La regla marcó tres buckets de mis otros proyectos como no conformes. La Lambda no los modificó, porque están fuera del alcance de la remediación.

<img width="1533" height="102" alt="Captura de pantalla de 2026-10-27 19-22-52" src="https://github.com/user-attachments/assets/b0837587-2597-453c-a94f-1b5affd6e348" />


<img width="1441" height="137" alt="Captura de pantalla de 2026-10-27 19-21-39" src="https://github.com/user-attachments/assets/662aa25b-f7aa-4f77-b643-c0293cd00df9" />


### Remediación automática del bucket de prueba
Después de crear `prueba-seguridad-2407`, la Lambda le agregó sola la política `DenyInsecureTransport`.

<img width="1465" height="79" alt="Captura de pantalla de 2026-10-27 19-32-20" src="https://github.com/user-attachments/assets/335db163-8973-47ef-af46-79bab65c7534" />


Config volvió a evaluarlo y pasó a conforme.

<img width="1448" height="80" alt="Captura de pantalla de 2026-10-27 19-28-22" src="https://github.com/user-attachments/assets/c3aa98c9-84cc-4ce2-a52b-f19a968d94c3" />


### Aviso por email
<img width="1080" height="853" alt="photo_5120611378283613474_y" src="https://github.com/user-attachments/assets/ac036b2f-cd8f-444a-b504-fe1385f65d32" />


## Problemas que resolví
- **GuardDuty no se pudo activar:** el diseño original incluía Amazon GuardDuty, pero AWS rechazó la creación del detector con un error `SubscriptionRequiredException`. Lo saqué del proyecto, y el resto (CloudTrail, Config y la remediación) siguió funcionando sin cambios.
- **Verificación antes de desplegar:** Config y GuardDuty admiten un solo recurso por región, así que consulté si ya existía una configuración activa antes de aplicar, para evitar un conflicto.
- **Alcance de la automatización:** al ver que la regla marcaba buckets de otros proyectos, confirmé que la limitación por prefijo evita modificar recursos que no corresponde tocar.

## Qué aprendí
- Una remediación automática necesita límites claros: permisos mínimos y un alcance acotado para no afectar recursos reales.
- Config evalúa la configuración y EventBridge conecta esa evaluación con una acción, sin servidores.
- La columna "Remediation action" de Config aparece como "Not set" porque implementé la remediación por otro camino (EventBridge + Lambda) y no con las acciones de remediación propias de Config.
- Algunos servicios de seguridad (como GuardDuty) pueden no estar disponibles según el tipo de cuenta.

## Costo
Bajo. Config cobra por recurso registrado y por evaluación, y CloudTrail y S3 cuestan centavos con este volumen. Levanté la infraestructura, hice las pruebas y la destruí el mismo día para no dejar Config encendido.aws-security-baseline
