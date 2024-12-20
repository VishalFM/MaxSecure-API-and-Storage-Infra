from sqlalchemy import func
from app.models.model import Source
from app.extensions import db

def insert_sources(sources):
    try:
        source_objects = [Source(Name=source['Name']) for source in sources]
        validate_and_insert_sources(source_objects)
        db.session.commit()
        return {"message": f"{len(sources)} sources successfully inserted."}
    except Exception as e:
        db.session.rollback()
        return {"error": f"An error occurred while inserting the sources: {str(e)}"}

def validate_and_insert_sources(sources_data, ignore_existing_sources=False):
    try:
        sources_to_insert = []
        already_processed = set()

        for source in sources_data:
            source_name = source.get('Name')

            if not source_name:
                continue

            normalized_source_name = source_name.casefold()

            if normalized_source_name in already_processed:
                continue

            existing_source = db.session.query(Source).filter(
                func.lower(Source.Name) == normalized_source_name
            ).first()

            if existing_source:
                if not ignore_existing_sources:
                    return {"error": f"Source '{source_name}' already exists."}, False
            else:
                sources_to_insert.append(Source(Name=source_name))
                already_processed.add(normalized_source_name)

        if sources_to_insert:
            db.session.add_all(sources_to_insert)
            db.session.commit()

        return {"message": f"{len(sources_to_insert)} sources successfully inserted."}, True
    except Exception as e:
        db.session.rollback()
        return {"error": f"An error occurred while validating sources: {str(e)}"}, False

def get_source_ids(sources):
    sources_casefolded = [source.casefold() for source in sources]
    source_name_map = {source.casefold(): source for source in sources}
    return {
        source_name_map[record.Name.casefold()]: record.ID
        for record in db.session.query(Source)
        .filter(db.func.lower(Source.Name).in_(sources_casefolded))
        .all()
    }

def get_source_name_by_id(vendor_id):
    source = db.session.query(Source).filter(Source.ID == vendor_id).first()
    return source.Name if source else None