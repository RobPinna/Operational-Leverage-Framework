from app.db import SessionLocal
from app.services.assessment_service import create_demo_scenario


def main():
    with SessionLocal() as db:
        for scenario in ["RiadGroup Hospitality", "DesertAid NGO"]:
            assessment = create_demo_scenario(db, scenario)
            print(f"Seeded: #{assessment.id} - {assessment.company_name}")


if __name__ == "__main__":
    main()
