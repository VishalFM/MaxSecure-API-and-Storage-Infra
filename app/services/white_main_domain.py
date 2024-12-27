from app.models.model import WhiteMainDomainURL
from app.extensions import db
from datetime import datetime

def insert_white_main_domain_url(data):
    try:
        existing_record = WhiteMainDomainURL.query.filter_by(URL=data['URL'], MD5=data['MD5']).first()

        if existing_record:
            existing_record.counter += 1
            existing_record.update_date = datetime.utcnow()  

            db.session.commit()
            return True
        else:
            white_main_domain_url = WhiteMainDomainURL(
                URL=data['URL'],
                MD5=data['MD5'],
                EntryStatus=data['EntryStatus'],
                Vendor=data.get('Vendor'),
                counter=data.get('counter', 0),
                insert_date=datetime.utcnow(),  
                update_date=datetime.utcnow()   
            )

            db.session.add(white_main_domain_url)   
            db.session.commit()
            return True

    except Exception as e:
        db.session.rollback()
        return {"error": str(e), "inserted": False}
