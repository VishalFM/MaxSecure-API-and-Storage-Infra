from app.extensions import db
from sqlalchemy import CheckConstraint

class FileType(db.Model):
    __tablename__ = 'FileType'

    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Type = db.Column(db.String(255), nullable=False)
    signatures = db.relationship("Signature", back_populates="file_type")
    
    def __init__(self, Type):
        self.Type = Type

    def __repr__(self):
        return f"<FileType ID={self.ID} Type={self.Type}>"
    
class Source(db.Model):
    __tablename__ = 'Source'

    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Name = db.Column(db.String(255), nullable=False)
    signatures = db.relationship("Signature", back_populates="source")
    malicious_urls = db.relationship('MaliciousURLs', back_populates='source')

    def __init__(self, Name):
        self.Name = Name

    def __repr__(self):
        return f"<Source(ID={self.ID}, Name={self.Name})>"
    
class SpywareCategory(db.Model):
    __tablename__ = 'SpywareCategory'

    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Category = db.Column(db.String(255), nullable=False)
    spyware_names = db.relationship('SpywareName', back_populates='spyware_category')

    def __init__(self, Category):
        self.Category = Category

    def __repr__(self):
        return f"<SpywareCategory(ID={self.ID}, Category={self.Category})>"

class SpywareName(db.Model):
    __tablename__ = 'SpywareName'

    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Name = db.Column(db.String(255), nullable=False)
    SpywareCategoryID = db.Column(db.Integer, db.ForeignKey('SpywareCategory.ID'), nullable=False)
    spyware_category = db.relationship('SpywareCategory', back_populates='spyware_names')
    signatures = db.relationship('Signature', back_populates='spyware_name')

    def __init__(self, Name, SpywareCategoryID):
        self.Name = Name
        self.SpywareCategoryID = SpywareCategoryID

    def __repr__(self):
        return f"<SpywareName(ID={self.ID}, Name={self.Name}, SpywareCategoryID={self.SpywareCategoryID})>"
  
class Signature(db.Model):
    __tablename__ = 'Signature'

    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Signature = db.Column(db.String(255), nullable=False)
    EntryStatus = db.Column(db.Integer, nullable=False)
    InsertDate = db.Column(db.DateTime, nullable=False, default=db.func.now())
    UpdateDate = db.Column(db.DateTime, nullable=False, default=db.func.now(), onupdate=db.func.now())
    SpywareNameID = db.Column(db.Integer, db.ForeignKey('SpywareName.ID'), nullable=False)
    HitsCount = db.Column(db.Integer, default=0)
    SourceID = db.Column(db.Integer, db.ForeignKey('Source.ID'), nullable=False)
    FileTypeID = db.Column(db.Integer, db.ForeignKey('FileType.ID'), nullable=False)
    SHA256 = db.Column(db.String(300))  
    OS = db.Column(db.String(50))       

    spyware_name = db.relationship("SpywareName", back_populates="signatures")
    source = db.relationship("Source", back_populates="signatures")
    file_type = db.relationship("FileType", back_populates="signatures")
    white_file_names = db.relationship('WhiteFileName', back_populates='signature')
    hits = db.relationship('Hits', back_populates='signature')

    @property
    def SpywareInfo(self):
        if self.spyware_name and self.spyware_name.category:
            return f"{self.spyware_name.category.Category} - {self.spyware_name.Name}"
        return None

    def __init__(self, Signature, EntryStatus, SpywareNameID, SourceID, FileTypeID, HitsCount=0, SHA256=None, OS=None):
        self.Signature = Signature
        self.EntryStatus = EntryStatus
        self.SpywareNameID = SpywareNameID
        self.SourceID = SourceID
        self.FileTypeID = FileTypeID
        self.HitsCount = HitsCount
        self.SHA256 = SHA256
        self.OS = OS

    def __repr__(self):
        return f"<Signature(ID={self.ID}, Signature={self.Signature}, EntryStatus={self.EntryStatus}, SHA256={self.SHA256}, OS={self.OS})>"

class WhiteFileName(db.Model):
    __tablename__ = 'WhiteFileName'

    ID = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(255), nullable=False)
    SignatureTableID = db.Column(db.Integer, db.ForeignKey('Signature.ID', ondelete='CASCADE'), nullable=False)
    signature = db.relationship('Signature', back_populates='white_file_names')

    def __repr__(self):
        return f'<WhiteFileName {self.Name}>'
    
class Hits(db.Model):
    __tablename__ = 'Hits'
    
    ID = db.Column(db.Integer, primary_key=True)
    SignatureTableID = db.Column(db.Integer, db.ForeignKey('Signature.ID'), nullable=False)
    Hits = db.Column(db.Integer, nullable=False)
    signature = db.relationship('Signature', back_populates='hits')

class MaliciousURLs(db.Model):
    __tablename__ = 'MaliciousURLs'

    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    URL = db.Column(db.String(255), nullable=False, unique=True)
    VendorID = db.Column(db.Integer, db.ForeignKey('Source.ID'), nullable=False)
    EntryStatus = db.Column(db.String(50), nullable=False)
    Score = db.Column(db.Float, nullable=True, default=0.0)
    MD5 = db.Column(db.String(32), nullable=False, unique=True)
    MainDomain = db.Column(db.String(255), nullable=True)
    Main_domain_MD5 = db.Column(db.String(32), nullable=True)
    source = db.relationship('Source', back_populates='malicious_urls')

    def __init__(self, URL, VendorID, EntryStatus, Score=0.0, MD5=None, MainDomain=None, Main_domain_MD5=None):
        self.URL = URL
        self.VendorID = VendorID
        self.EntryStatus = EntryStatus
        self.Score = Score
        self.MD5 = MD5
        self.MainDomain = MainDomain
        self.Main_domain_MD5 = Main_domain_MD5

    def __repr__(self):
        return f"<MaliciousURLs(ID={self.ID}, URL={self.URL}, VendorID={self.VendorID}, EntryStatus={self.EntryStatus}, Score={self.Score}, MainDomain={self.MainDomain})>"

class WhiteMainDomainURL(db.Model):
    __tablename__ = "WhiteMainDomainURL"

    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    URL = db.Column(db.Text, nullable=False)
    MD5 = db.Column(db.CHAR(32), nullable=False)
    EntryStatus = db.Column(db.Integer, nullable=False)
    Vendor = db.Column(db.String(100), nullable=True)
    counter = db.Column(db.Integer, default=0)

    def __init__(self, URL, MD5, EntryStatus, Vendor=None, counter=0):
        self.URL = URL
        self.MD5 = MD5
        self.EntryStatus = EntryStatus
        self.Vendor = Vendor
        self.counter = counter

    def __repr__(self):
        return f"<WhiteMainDomainURL(ID={self.ID}, URL={self.URL}, MD5={self.MD5}, EntryStatus={self.EntryStatus}, Vendor={self.Vendor}, counter={self.counter})>"
    