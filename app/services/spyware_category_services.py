from app.models.model import SpywareCategory
from app.extensions import db

def insert_spyware_categories(categories):
    """
    Inserts multiple spyware category records into the database in bulk, skipping duplicates.
    """
    try:
        # Step 1: Validate input - Ensure each category has a valid 'Category' field
        valid_categories = [cat for cat in categories if cat.get('Category') and isinstance(cat['Category'], str)]
        print("valid_categories ", valid_categories)
        if not valid_categories:
            return {"error": "No valid categories provided or missing 'Category' field."}, 400

        # Step 2: Normalize input and check for existing categories in the database
        input_categories = [cat['Category'].strip() for cat in valid_categories]
        print("input_categories ", input_categories)
        existing_categories = set(
            category[0].lower() for category in db.session.query(SpywareCategory.Category).filter(
                SpywareCategory.Category.in_(input_categories)
            ).all()
        )
        print("existing_categories ", existing_categories)

        # Step 3: Filter out categories that already exist in the database
        new_categories = [
            cat['Category'].strip() for cat in valid_categories if cat['Category'].strip().lower() not in existing_categories
        ]
        print("new_categories ", new_categories)

        if not new_categories:
            return {"message": "All provided categories already exist in the database."}, 200

        # Step 4: Create SpywareCategory objects for new categories
        category_objects = [SpywareCategory(Category=cat) for cat in new_categories]

        print("category_objects ", category_objects)
        # Step 5: Bulk insert into the database
        db.session.bulk_save_objects(category_objects)

        # Step 6: Commit the transaction
        db.session.commit()

        # Step 7: Return success message with the number of inserted records
        return {"message": f"{len(new_categories)} spyware categories successfully inserted."}, 201
    except Exception as e:
        # Step 8: Rollback in case of error and return an error message
        db.session.rollback()
        return {"error": f"An error occurred while inserting the spyware categories: {str(e)}"}, 500


