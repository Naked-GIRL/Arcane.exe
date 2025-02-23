import os
import pefile
import re
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from fpdf import FPDF
import subprocess

# Fonction pour créer la structure de dossiers
def create_folder_structure(base_dir):
    directories = ['passwords', 'images', 'requests', 'strings', 'reports']
    for dir_name in directories:
        os.makedirs(os.path.join(base_dir, dir_name), exist_ok=True)

# Extraction des chaînes de caractères d'un fichier PE (.exe)
def extract_strings(exe_path):
    result = subprocess.run(['strings', exe_path], stdout=subprocess.PIPE, text=True)
    return result.stdout

# Recherche des mots de passe dans les chaînes
def find_passwords(strings):
    return [line for line in strings.splitlines() if 'password' in line.lower()]

# Recherche des requêtes HTTP dans les chaînes
def find_http_requests(strings):
    url_pattern = re.compile(r"https?://[^\s\"'>]+")  # Capture les URL
    return list(set(url_pattern.findall(strings)))  # Suppression des doublons

# Analyser les sections du fichier PE
def analyze_pe_sections(exe_path):
    pe = pefile.PE(exe_path)
    return [
        {
            "Name": section.Name.decode(errors='ignore').strip(),
            "Size": section.SizeOfRawData,
            "Virtual Address": hex(section.VirtualAddress),
            "Characteristics": hex(section.Characteristics)
        }
        for section in pe.sections
    ]

# Analyser les imports du fichier EXE
def analyze_imports(exe_path):
    pe = pefile.PE(exe_path)
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return [entry.dll.decode(errors='ignore') for entry in pe.DIRECTORY_ENTRY_IMPORT]
    return []

# Génération d'un rapport PDF
def generate_pdf_report(base_dir, exe_path, sections, imports, passwords, requests):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="Rapport d'analyse de fichier EXE", ln=True, align="C")
    pdf.ln(10)

    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Fichier analysé : {exe_path}", ln=True)
    pdf.cell(200, 10, txt=f"Chemin d'analyse : {base_dir}", ln=True)
    pdf.ln(10)

    pdf.cell(200, 10, txt="Imports analysés :", ln=True)
    for imp in imports:
        pdf.cell(200, 10, txt=f"- {imp}", ln=True)
    pdf.ln(10)

    pdf.cell(200, 10, txt="Sections du fichier EXE :", ln=True)
    for section in sections:
        pdf.cell(200, 10, txt=f"- {section['Name']} : Taille = {section['Size']} | Adresse virtuelle = {section['Virtual Address']}", ln=True)
    pdf.ln(10)

    pdf.cell(200, 10, txt="Mots de passe trouvés :", ln=True)
    for password in passwords:
        pdf.cell(200, 10, txt=f"- {password}", ln=True)
    pdf.ln(10)

    pdf.cell(200, 10, txt="Requêtes HTTP détectées :", ln=True)
    for request in requests:
        pdf.cell(200, 10, txt=f"- {request}", ln=True)
    pdf.ln(10)

    pdf_output = os.path.join(base_dir, 'reports', 'analysis_report.pdf')
    pdf.output(pdf_output)
    print(f"Rapport PDF généré : {pdf_output}")

# Fonction principale d'analyse du fichier .exe
def analyze_exe(exe_path, progress_label, progress_bar):
    base_dir = 'analysis_results'
    create_folder_structure(base_dir)

    progress_label.config(text="Analyse en cours...")
    progress_bar.start(10)

    strings = extract_strings(exe_path)
    passwords = find_passwords(strings)
    requests = find_http_requests(strings)

    with open(os.path.join(base_dir, 'passwords', 'found_passwords.txt'), 'w') as f:
        f.write('\n'.join(passwords))

    with open(os.path.join(base_dir, 'requests', 'found_requests.txt'), 'w') as f:
        f.write('\n'.join(requests))

    sections = analyze_pe_sections(exe_path)
    imports = analyze_imports(exe_path)

    generate_pdf_report(base_dir, exe_path, sections, imports, passwords, requests)

    progress_label.config(text="Analyse terminée!")
    progress_bar.stop()
    messagebox.showinfo("Analyse terminée", f"Les résultats sont stockés dans : {base_dir}")

# Fenêtre Tkinter pour choisir le fichier .exe
def browse_file(progress_label, progress_bar):
    file_path = filedialog.askopenfilename(filetypes=[("Executable Files", "*.exe")])
    if file_path:
        analyze_exe(file_path, progress_label, progress_bar)

# Création de l'interface graphique
def create_gui():
    root = tk.Tk()
    root.title("Analyseur de fichiers .exe")
    root.geometry("500x300")

    title_label = tk.Label(root, text="Sélectionner un fichier .exe à analyser", font=("Arial", 14))
    title_label.pack(pady=10)

    progress_label = tk.Label(root, text="", font=("Arial", 12))
    progress_label.pack(pady=10)

    progress_bar = ttk.Progressbar(root, length=300, mode='indeterminate')
    progress_bar.pack(pady=10)

    browse_button = tk.Button(root, text="Choisir un fichier", font=("Arial", 12), command=lambda: browse_file(progress_label, progress_bar))
    browse_button.pack(pady=20)

    root.mainloop()

# Exécution principale
if __name__ == "__main__":
    create_gui()
