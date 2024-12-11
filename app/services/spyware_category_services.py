from sqlalchemy import func
from app.models.model import SpywareCategory
from app.extensions import db

def insert_spyware_categories(categories):
    """
    Inserts multiple spyware category records into the database in bulk, skipping duplicates.
    Allows insertion of categories case-insensitively.
    """
    try:
        # Step 1: Validate input - Ensure each category has a valid 'Category' field
        valid_categories = [cat for cat in categories if cat.get('Category') and isinstance(cat['Category'], str)]
        print("valid_categories ", valid_categories)
        if not valid_categories:
            return {"error": "No valid categories provided or missing 'Category' field."}, 400

        # Step 2: Normalize input categories (strip and case-fold for comparison)
        input_categories = [cat['Category'].strip() for cat in valid_categories]
        input_categories_casefold = [cat.casefold() for cat in input_categories]  # Normalize case for comparison
        print("input_categories_casefold ", input_categories_casefold)

        # Step 3: Fetch existing categories from the database (case-insensitive comparison)
        existing_categories = set(
            category[0].casefold() for category in db.session.query(SpywareCategory.Category).filter(
                func.lower(SpywareCategory.Category).in_(input_categories_casefold)
            ).all()
        )
        print("existing_categories ", existing_categories)

        # Step 4: Filter out categories that already exist (case-insensitive check)
        new_categories = [
            cat for cat in input_categories if cat.casefold() not in existing_categories
        ]
        print("new_categories ", new_categories)

        if not new_categories:
            return {"message": "All provided categories already exist in the database."}, 200

        # Step 5: Create SpywareCategory objects for new categories
        category_objects = [SpywareCategory(Category=cat) for cat in new_categories]

        print("category_objects ", category_objects)
        # Step 6: Bulk insert into the database
        db.session.bulk_save_objects(category_objects)

        # Step 7: Commit the transaction
        db.session.commit()

        # Step 8: Return success message with the number of inserted records
        return {"message": f"{len(new_categories)} spyware categories successfully inserted."}, 201
    except Exception as e:
        # Step 9: Rollback in case of error and return an error message
        db.session.rollback()
        return {"error": f"An error occurred while inserting the spyware categories: {str(e)}"}, 500

# used in adding Signature
def get_or_create_spyware_category(category_name):
    """
    Check if the SpywareCategory exists; if not, create it.
    
    Args:
        category_name (str): The spyware category name.

    Returns:
        int: ID of the SpywareCategory.
    """
    category_name_lower = category_name.casefold()
    category = db.session.query(SpywareCategory).filter(
        db.func.lower(SpywareCategory.Category) == category_name_lower
    ).first()

    if not category:
        category = SpywareCategory(Category=category_name)
        db.session.add(category)
        db.session.flush()  # Save to DB and assign ID

    return category.ID