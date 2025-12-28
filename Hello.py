
"""
Mijn eerste Python script voor OT Cybersecurity
Author: Jan Van der Linden
Date: 2024-12-28
Purpose: Introduction to Python for OT Security
"""
def print_banner(text):
    """
    Print een mooie banner met tekst
    Args:
    text (str): Tekst om weer te geven
    """
    length = len(text)
    border = "=" * (length + 4)
    print(f"\n{border}")
    print(f" {text} ")  
    print(f"{border}\n")
def display_info():
    """Toon student en cursus informatie"""
    # Persoonlijke info - WIJZIG DEZE!
    student_name = "Tim Flamee" # TODO: Jouw naam
    goal = "OT Cybersecurity Officer"
    print(f"Student: {student_name}")
    print(f"Doel: {goal}")
def display_skills():
    """Toon lijst van te leren skills"""
    skills = [
        "Python Programming",
        "Data Analysis (Pandas, NumPy)",
        "Data Visualization (Matplotlib, Plotly)",
        "Machine Learning (Scikit-learn)",
        "Deep Learning (PyTorch)",
        "OT Protocol Analysis (Modbus, OPC-UA, IEC 61850)",
        "Anomaly Detection & PyOD",
        "SIEM Integration","IEC 62443 Framework",
        "Network Security Monitoring"
    ]
    print(f"\nSkills to Master ({len(skills)}):")
    for i, skill in enumerate(skills, 1):
        print(f" {i:2d}. {skill}")
def display_statistics():
    """Bereken en toon cursus statistieken"""
# Cursus statistieken
total_sessions = 56
hours_per_session = 1.5
sessions_per_week = 3 # Aanpasbaar
# Berekeningen
total_hours = total_sessions * hours_per_session
weeks_needed = total_sessions / sessions_per_week
print(f"\nCursus Statistieken:")
print(f" • Totaal sessies: {total_sessions}")
print(f" • Uren per sessie: {hours_per_session}")
print(f" • Totaal leeruren: {total_hours}")
print(f" • Geschatte weken: {weeks_needed:.1f} (bij {sessions_per_week} sessies/week)")
print(f" • Geschatte maanden: {weeks_needed/4:.1f}")
def main():
    """Main functie - entry point van programma"""
    # Print hoofdtitel
    print_banner("OT CYBERSECURITY LEARNING JOURNEY")
    # Toon alle informatie
    display_info()
    display_skills()
    display_statistics()
    # Afsluiting
    print_banner("Let's start coding!")
    print("Project: ot-cybersecurity-learning")
    print("Editor: Visual Studio Code")
    print("Tools: Python, Git, GitHub")
    print("\n Development environment is ready!\n")
# Entry point checkif __name__ == "__main__":
main()