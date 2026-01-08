import subprocess
import re
import time
from datetime import datetime
import random
import string
import sys

WEBHOOK_URL = "https://discord.com/api/webhooks/1457796530193956968/cynx0qmH3HNCi2EOGKa8Y14NxQ7gd0omMH6m9psI-FGUp43SSP0rvHUJQtdLco4o6Cuq"

CHECK_PATHS = [
    "/storage/emulated/0/Android/data/com.dts.freefireth/files/MReplays",
    "/storage/emulated/0/Android/data/com.dts.freefiremax/files/MReplays",
    "/storage/emulated/0/Download",
]

PACKAGES_TO_CHECK = ["com.dts.freefireth", "com.dts.freefiremax"]


def adb_shell(args):
    try:
        result = subprocess.check_output(
            ["adb", "shell"] + args, stderr=subprocess.STDOUT
        )
        return result.decode("utf-8", errors="ignore")
    except subprocess.CalledProcessError as e:
        return e.output.decode("utf-8", errors="ignore")


def gerar_chave(tamanho=6):
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=tamanho))


def enviar_chave_webhook(chave):
    """Envia apenas a chave para o webhook"""
    import requests
    
    payload = {
        "username": "Nyache Scanner",
        "avatar_url": "https://i.supaimg.com/bdea323d-8607-4047-9d59-28a544d66cf3.jpg",
        "content": f"🔑 Nova chave de escaneamento gerada: `{chave}`"
    }
    
    try:
        requests.post(WEBHOOK_URL, json=payload, timeout=5)
    except Exception:
        print("⚠️ Não foi possível enviar a chave para o webhook.")


def solicitar_chave(key_gerada):
    print("╔═╗╦ ╦╔═╗ ╔═╗╔═╗╦  ╦╔═╗")
    print("╠═╣║║║║╣  ╠═╣║  ║  ║║ ║")
    print("╩ ╩╚╩╝╚═╝╩╩ ╩╚═╝╩═╝╩╚═╝")    
    entrada = input("Please set scan key: ")
    
    if entrada != key_gerada:
        print("❌ Incorrect key, script crashing...")
        sys.exit(1)
    
    print("✅ Successful identification, scanning...")

def get_system_boot_time():
    try:
        uptime_output = adb_shell(["cat", "/proc/uptime"]).split()
        if uptime_output:
            uptime_seconds = float(uptime_output[0])
            current_time = time.time()
            boot_time = current_time - uptime_seconds
            return boot_time
    except Exception:
        return None


def scan_arquivos_modificados_truncados():
    relatorio = []
    boot_time = get_system_boot_time()
    
    print("[+] Scanning for modified/truncated files...")

    for base_path in CHECK_PATHS:
        output = adb_shell(["find", base_path, "-type", "f"])
        arquivos = output.strip().splitlines()

        for arq in arquivos:
            if not arq:
                continue

            stat = adb_shell(["stat", arq])

            mtime_match = re.search(
                r"Modify:\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", stat
            )
            size_match = re.search(r"Size:\s+(\d+)", stat)

            if not mtime_match or not size_match:
                continue

            try:
                mod_time = datetime.strptime(
                    mtime_match.group(1), "%Y-%m-%d %H:%M:%S"
                ).timestamp()
                size = int(size_match.group(1))
            except:
                continue

            if boot_time and mod_time > boot_time:
                if size == 0:
                    relatorio.append(
                        f"🛑 ARQUIVO TRUNCADO (0 bytes) E MODIFICADO PÓS-BOOT: {arq}"
                    )
                    relatorio.append(f"   - Modificado em: {mtime_match.group(1)}")
                else:
                    relatorio.append(f"✏️ ARQUIVO MODIFICADO PÓS-BOOT: {arq}")
                    relatorio.append(f"   - Modificado em: {mtime_match.group(1)}")
            else:
                if size == 0:
                    relatorio.append(f"⚠️ Arquivo truncado (0 bytes): {arq}")

    return relatorio


def scan_arquivos_deletados_logcat():
    print("[+] Scanning for deleted files in logcat...")
    
    filtro_delecao = r"unlink|delete|remove|rm -rf|rmdir|removed package"
    try:
        logcat_output = subprocess.check_output(
            ["adb", "logcat", "-d"], stderr=subprocess.DEVNULL
        ).decode("utf-8", errors="ignore")
    except Exception:
        return []

    linhas_delecao = []
    for linha in logcat_output.splitlines():
        if re.search(filtro_delecao, linha, re.I):
            linhas_delecao.append(f"🗑️ {linha.strip()}")

    return linhas_delecao


def detect_alteracao_manual_horario():
    print("[+] Checking for manual time changes...")
    relatorio = []

    output = subprocess.getoutput("adb logcat -d | grep -i 'time changed'")
    if output.strip():
        relatorio.append("⏰ ALTERAÇÃO MANUAL DE HORÁRIO DETECTADA VIA LOGCAT:")
        relatorio.extend(output.strip().splitlines())
    else:
        auto_time = adb_shell(["settings", "get", "global", "auto_time"]).strip()
        if auto_time == "0":
            relatorio.append(
                "⚠️ Horário automático desligado - possível alteração manual."
            )

    return relatorio


def comparar_instalacao_obb():
    print("[+] Comparing APK installation with OBB files...")
    relatorio_total = []

    for package_name in PACKAGES_TO_CHECK:
        relatorio = [f"\n🎮 VERIFICANDO PACOTE: {package_name}"]

        try:
            install_info = adb_shell(["dumpsys", "package", package_name])
            install_time = None

            for linha in install_info.splitlines():
                if "firstInstallTime" in linha:
                    match = re.search(r"firstInstallTime=(\d+)", linha)
                    if match:
                        install_time_ms = int(match.group(1))
                        install_time = datetime.fromtimestamp(install_time_ms / 1000.0)
                        relatorio.append(
                            f"📱 APK Instalado em: {install_time.strftime('%Y-%m-%d %H:%M:%S')}"
                        )
                        break

            if not install_time:
                relatorio.append(
                    "❌ Não foi possível encontrar a data de instalação do APK."
                )
                relatorio_total.extend(relatorio)
                continue

        except Exception:
            continue

        obb_dir = f"/storage/emulated/0/Android/obb/{package_name}/"
        try:
            output = adb_shell(["find", obb_dir, "-name", "*.obb", "-type", "f"])
            obb_files = output.strip().splitlines()

            if not obb_files:
                continue

            latest_obb = None
            latest_mtime = 0

            for obb in obb_files:
                if not obb:
                    continue
                stat = adb_shell(["stat", obb])
                mtime_match = re.search(
                    r"Modify:\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", stat
                )
                if mtime_match:
                    obb_mod_time = datetime.strptime(
                        mtime_match.group(1), "%Y-%m-%d %H:%M:%S"
                    ).timestamp()
                    if obb_mod_time > latest_mtime:
                        latest_mtime = obb_mod_time
                        latest_obb = (obb, mtime_match.group(1))

            if latest_obb:
                obb_path, obb_mod_str = latest_obb
                obb_time = datetime.fromtimestamp(latest_mtime)

                time_diff = obb_time - install_time
                diff_days = time_diff.days

                if diff_days < -7:
                    relatorio.append(
                        f"🚨 ANOMALIA: O arquivo OBB é muito mais antigo que a instalação do APK. Diferença: {-diff_days} dias."
                    )
                elif diff_days > 1:
                    relatorio.append(
                        f"⚠️ AVISO: O arquivo OBB é mais novo que a instalação do APK. Diferença: {diff_days} dias."
                    )
        except Exception:
            continue

        relatorio_total.extend(relatorio)

    return relatorio_total


def exibir_resultados_terminal(titulo, resultados, cor_simbolo="="):
    """Exibe os resultados no terminal de forma formatada"""
    if not resultados:
        return
    print(f"📋 {titulo}")
    
    for resultado in resultados:
        print(resultado)


def main():
    key = gerar_chave()
    enviar_chave_webhook(key)
    solicitar_chave(key)
    
    print("\n[🔍] Iniciando verificações de segurança...")
    
    rel_horario = detect_alteracao_manual_horario()
    rel_modificados = scan_arquivos_modificados_truncados()
    rel_deletados = scan_arquivos_deletados_logcat()
    rel_obb = comparar_instalacao_obb()
    
    exibir_resultados_terminal("ALTERAÇÃO DE HORÁRIO", rel_horario, "⏰")
    exibir_resultados_terminal("ARQUIVOS MODIFICADOS/TRUNCADOS", rel_modificados, "✏️")
    exibir_resultados_terminal("ARQUIVOS DELETADOS", rel_deletados, "🗑️")
    exibir_resultados_terminal("VERIFICAÇÃO APK & OBB", rel_obb, "🎮")
    
    tudo_limpo = not any([rel_horario, rel_modificados, rel_deletados, rel_obb])
    
if tudo_limpo:
        print("✅ Successfuel in scanning")
    else:
        print("❗ Suspicious Activity Detected")


if __name__ == "__main__":
    main()
