# Build para GBox

Este proyecto está preparado para compilar la IPA sin firma de distribución de Apple.

La workflow de GitHub Actions usa un runner macOS, compila el target `3105` para `iphoneos` con `CODE_SIGNING_ALLOWED=NO`, empaqueta el `.app` como IPA y lo deja como artifact `Javi-Gamer-unsigned`.

No requiere certificado, provisioning profile ni Mac local.
