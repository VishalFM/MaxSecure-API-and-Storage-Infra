from app.models.model import SpywareName, SpywareCategory
from app.extensions import db

def insert_spyware_names_with_category(spyware_data):
    try:
        # Step 1: Validate input
        valid_entries = [
            item for item in spyware_data
            if item.get('Name') and item.get('Category') and isinstance(item['Name'], str) and isinstance(item['Category'], str)
        ]
        print("valid_entries:", valid_entries)

        if not valid_entries:
            return {"error": "Invalid input. Each record must contain 'Name' and 'Category'."}, 400

        # Step 2: Normalize input categories
        input_categories = {item['Category'].strip().casefold() for item in valid_entries}  # Strip and normalize
        print("input_categories:", input_categories)

        # Fetch existing categories in a single query with case-insensitive matching using casefold
        existing_categories = {
            category.Category.casefold(): category.ID  # Use casefold for case-insensitive comparison
            for category in db.session.query(SpywareCategory).filter(
                SpywareCategory.Category.in_([cat for cat in input_categories])  # No need for casefold in query here
            ).all()
        }
        print("existing_categories:", existing_categories)

        # Step 3: Identify new categories
        new_categories = input_categories - set(existing_categories.keys())
        print("new_categories:", new_categories)

        # Step 4: Insert new categories and update the mapping
        if new_categories:
            new_category_objects = [SpywareCategory(Category=cat) for cat in new_categories]
            db.session.add_all(new_category_objects)
            db.session.flush()  # Commit the session to persist new categories

            print("new_category_objects:", new_category_objects)

            # Update existing_categories with newly added ones
            for category in new_category_objects:
                existing_categories[category.Category.casefold()] = category.ID

        print("existing_categories (updated):", existing_categories)

        # Step 5: Prepare SpywareName objects
        spyware_name_entries = set(
            (item['Name'].strip(), existing_categories[item['Category'].strip().casefold()])
            for item in valid_entries
        )
        print("spyware_name_entries:", spyware_name_entries)

        # Fetch existing spyware names to exclude duplicates
        existing_spyware_names = {
            (name.Name, name.SpywareCategoryID)
            for name in db.session.query(SpywareName).filter(
                SpywareName.SpywareCategoryID.in_(existing_categories.values())
            ).all()
        }
        print("existing_spyware_names:", existing_spyware_names)

        # Identify new SpywareName entries
        new_spyware_names = spyware_name_entries - existing_spyware_names
        print("new_spyware_names:", new_spyware_names)

        # Create SpywareName objects for insertion
        spyware_name_objects = [
            SpywareName(Name=name, SpywareCategoryID=category_id)
            for name, category_id in new_spyware_names
        ]

        # Step 6: Bulk insert new Spyware Names
        if spyware_name_objects:
            db.session.bulk_save_objects(spyware_name_objects)

        # Step 7: Commit the transaction
        db.session.commit()
        print("Transaction committed.")

        # Step 8: Return success message
        return {
            "message": f"{len(spyware_name_objects)} spyware names successfully inserted.",
            "duplicates": list(existing_spyware_names & spyware_name_entries),
            "spyware_names": [{"Name": obj.Name, "SpywareCategoryID": obj.SpywareCategoryID} for obj in spyware_name_objects]
        }, 201
    except Exception as e:
        # Rollback in case of error
        db.session.rollback()
        print("Transaction rolled back due to error:", e)
        return {"error": f"An error occurred while inserting spyware names: {str(e)}"}, 500
