from datetime import datetime


def registrar_respuesta(usuario):
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open("respuesta.log", "a", encoding="utf-8") as archivo:
        archivo.write(f"{fecha},USUARIO_BLOQUEADO,{usuario}\n")

    return fecha


intentos = {}

with open("eventos.log", "r", encoding="utf-8") as archivo:
    for linea in archivo:
        fecha, tipo, usuario = linea.strip().split(",")

        if tipo == "LOGIN_FALLIDO":
            if usuario not in intentos:
                intentos[usuario] = []

            intentos[usuario].append(fecha)


for usuario, registros in intentos.items():
    if len(registros) >= 3:
        print("ALERTA DE SEGURIDAD")
        print("Usuario:", usuario)
        print("INTENTOS FALLIDOS:", len(registros))
        print("PRIMER INTENTO:", registros[0])
        print("DETECCIÓN:", registros[2])

        inicio = datetime.strptime(registros[0], "%Y-%m-%d %H:%M:%S")
        deteccion = datetime.strptime(registros[2], "%Y-%m-%d %H:%M:%S")

        fecha_respuesta = registrar_respuesta(usuario)
        respuesta = datetime.strptime(fecha_respuesta, "%Y-%m-%d %H:%M:%S")

        mttd = (deteccion - inicio).total_seconds()
        mttr = (respuesta - deteccion).total_seconds()

        print("MTTD:", mttd, "segundos")
        print("MTTR:", mttr, "segundos")
        print("Acción aplicada: bloqueo de usuario")
        print("Respuesta:", fecha_respuesta)