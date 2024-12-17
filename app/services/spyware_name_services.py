from app.models.model import SpywareName, SpywareCategory
from app.extensions import db

def insert_spyware_names_with_category(spyware_data):
    try:
        valid_entries = [
            item for item in spyware_data
            if item.get('Name') and item.get('Category') and isinstance(item['Name'], str) and isinstance(item['Category'], str)
        ]

        if not valid_entries:
            return {"error": "Invalid input. Each record must contain 'Name' and 'Category'."}, 400

        input_categories = {item['Category'].strip().casefold() for item in valid_entries}

        existing_categories = {
            category.Category.casefold(): category.ID
            for category in db.session.query(SpywareCategory).filter(
                SpywareCategory.Category.in_([cat for cat in input_categories])
            ).all()
        }

        new_categories = input_categories - set(existing_categories.keys())

        if new_categories:
            new_category_objects = [SpywareCategory(Category=cat) for cat in new_categories]
            db.session.add_all(new_category_objects)
            db.session.flush()

            for category in new_category_objects:
                existing_categories[category.Category.casefold()] = category.ID

        spyware_name_entries = set(
            (item['Name'].strip(), existing_categories[item['Category'].strip().casefold()])
            for item in valid_entries
        )

        existing_spyware_names = {
            (name.Name, name.SpywareCategoryID)
            for name in db.session.query(SpywareName).filter(
                SpywareName.SpywareCategoryID.in_(existing_categories.values())
            ).all()
        }

        new_spyware_names = spyware_name_entries - existing_spyware_names

        spyware_name_objects = [
            SpywareName(Name=name, SpywareCategoryID=category_id)
            for name, category_id in new_spyware_names
        ]

        if spyware_name_objects:
            db.session.bulk_save_objects(spyware_name_objects)

        db.session.commit()

        return {
            "message": f"{len(spyware_name_objects)} spyware names successfully inserted.",
            "duplicates": list(existing_spyware_names & spyware_name_entries),
            "spyware_names": [{"Name": obj.Name, "SpywareCategoryID": obj.SpywareCategoryID} for obj in spyware_name_objects]
        }, 201
    except Exception as e:
        db.session.rollback()
        return {"error": f"An error occurred while inserting spyware names: {str(e)}"}, 500

def get_or_create_spyware_name(spyware_name, category_id):
    spyware_name_lower = spyware_name.casefold()
    spyware_name_entry = db.session.query(SpywareName).filter(
        db.func.lower(SpywareName.Name) == spyware_name_lower,
        SpywareName.SpywareCategoryID == category_id
    ).first()

    if not spyware_name_entry:
        spyware_name_entry = SpywareName(Name=spyware_name, SpywareCategoryID=category_id)
        db.session.add(spyware_name_entry)
        db.session.flush()

    return spyware_name_entry.ID
