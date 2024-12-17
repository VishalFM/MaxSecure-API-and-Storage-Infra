from sqlalchemy import func
from app.models.model import SpywareCategory
from app.extensions import db

def insert_spyware_categories(categories):
    try:
        valid_categories = [cat for cat in categories if cat.get('Category') and isinstance(cat['Category'], str)]
        if not valid_categories:
            return {"error": "No valid categories provided or missing 'Category' field."}, 400

        input_categories = [cat['Category'].strip() for cat in valid_categories]
        input_categories_casefold = [cat.casefold() for cat in input_categories]

        existing_categories = set(
            category[0].casefold() for category in db.session.query(SpywareCategory.Category).filter(
                func.lower(SpywareCategory.Category).in_(input_categories_casefold)
            ).all()
        )

        new_categories = [
            cat for cat in input_categories if cat.casefold() not in existing_categories
        ]

        if not new_categories:
            return {"message": "All provided categories already exist in the database."}, 200

        category_objects = [SpywareCategory(Category=cat) for cat in new_categories]
        db.session.bulk_save_objects(category_objects)
        db.session.commit()

        return {"message": f"{len(new_categories)} spyware categories successfully inserted."}, 201
    except Exception as e:
        db.session.rollback()
        return {"error": f"An error occurred while inserting the spyware categories: {str(e)}"}, 500

def get_or_create_spyware_category(category_name):
    category_name_lower = category_name.casefold()
    category = db.session.query(SpywareCategory).filter(
        db.func.lower(SpywareCategory.Category) == category_name_lower
    ).first()

    if not category:
        category = SpywareCategory(Category=category_name)
        db.session.add(category)
        db.session.flush()

    return category.ID
