# © Copyright 2026 - Carl OS Created by Mau-San.

# 1/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
# ------------------------------------------------------------------------------------------------
# Simple virus signature database.
# ------------------------------------------------------------------------------------------------
virus_signatures = [
"trojan"
"malware"
"keylogger"
"virus"
]
# ------------------------------------------------------------------------------------------------
# Function to scan a file.
# ------------------------------------------------------------------------------------------------
def scan_file(ruta):
print(f"Reviewing the file: {ruta") 
try:
with open(ruta, "r", errors="ignore") as f: 
  contenido = f.read()
  for firma in virus_signatures:
  if firma.lower() in contenido.lower():
    print("This file has been detected as malicious.")
    return 
    print("✅ Secure file.")
    except:
    print("🚫 Error 707: I could not read that file.")

# ------------------------------------------------------------------------------------------------
# Función principal
# ------------------------------------------------------------------------------------------------

def main():
print("Welcome to Carl OS Malware Detector.")
opcion = input("Scanning (1) file or (2) folder...")
if opcion == "1":
archivo = input("The file path..")
scan_file(archivo)
elif opcion == "2":
carpeta = input("The folder path..")
scan_folder(carpeta)
else:
print("Error 101: Option not found.")
# ------------------------------------------------------------------------------------------------
# Ejecuta solo si se llama directamente
# ------------------------------------------------------------------------------------------------
if__name__=="__main__":
main()
