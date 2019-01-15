from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, User, Category, Item

engine = create_engine('sqlite:///catalogitemswithusers.db?check_same_thread=False')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

lorem_ipsum = '''Lorem ipsum dolor sit amet, eu vix delicata vulputate percipitur, mea augue omnesque gubergren te, pro errem aliquam ei. No vis habeo ullum, fugit legere no quo. Eum debet assueverit in, at ferri rationibus has. Ad brute euismod petentium has. Fugit mollis reformidans eam ad, est ei tale deseruisse liberavisse. Adhuc atqui usu in, reque falli iuvaret at duo, eu quo sint malis rationibus.

Vel in tation verear mandamus, quo at malorum efficiantur. Et mel feugait deseruisse, zril albucius vix ex, in essent apeirian eos. Porro soluta ea sea, quaeque officiis nec an. Eos ex veritus omittam. Possim invenire conceptam eu vel.

In quot hendrerit cum, ad vocent expetendis vix. Est no oportere ocurreret constituto, est fugit discere ut. No timeam electram vis. Mei molestie percipit cu. Nec dicam placerat an, denique appellantur eu vel, ius et harum voluptaria. Sit legimus ocurreret hendrerit ea, diam invenire intellegebat vix ei. Usu ne alia enim suscipit, eius semper mel in.

At graeco torquatos pri. Est atqui percipit reformidans te, an eam mundi epicurei appareat, est accumsan adipisci ea. Ius quaestio philosophia et, pri cu porro liber dissentiet. Et his omnium integre, mollis minimum voluptatum no ius. Alii mediocrem repudiare mei id, no ridens nostrum mei, id ipsum facilis sed. Ad vocent albucius inimicus nec, ei brute iusto qui.

Ex modo sanctus sea. Reprimique necessitatibus in mei, corpora postulant ex pro. Vel no eripuit vituperatoribus, te his quem volumus mentitum. Nibh sale vel cu, sale adipisci intellegam ius ut.'''

# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

User1 = User(name="Robo Barista", email="email@example.com",
             picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png',
             auto_signin=False)
session.add(User1)
session.commit()

category1 = Category(name="Hockey", user=User1, user_id=User1.id)

session.add(category1)
session.commit()

item1 = Item(name="Stick", description=lorem_ipsum,
                     category=category1, category_id=category1.id, user=User1, user_id=User1.id)

session.add(item1)
session.commit()

item2 = Item(name="Skates", description=lorem_ipsum,
                     category=category1, category_id=category1.id, user=User1, user_id=User1.id)

session.add(item2)
session.commit()

item3 = Item(name="Puck", description=lorem_ipsum,
                     category=category1, category_id=category1.id, user=User1, user_id=User1.id)

session.add(item3)
session.commit()

###############################################

category2 = Category(name="Snowboarding", user=User1, user_id=User1.id)

session.add(category2)
session.commit()

item1 = Item(name="Goggles", description=lorem_ipsum,
                     category=category2, category_id=category2.id, user=User1, user_id=User1.id)

session.add(item1)
session.commit()

item2 = Item(name="Snowboard", description=lorem_ipsum,
                     category=category2, category_id=category2.id, user=User1, user_id=User1.id)

session.add(item2)
session.commit()


#####################################################

category3 = Category(name="Basketball", user=User1, user_id=User1.id)

session.add(category3)
session.commit()

item1 = Item(name="Basketball", description=lorem_ipsum,
                     category=category3, category_id=category3.id, user=User1, user_id=User1.id)

session.add(item1)
session.commit()

item2 = Item(name="Sneakers", description=lorem_ipsum,
                     category=category3, category_id=category3.id, user=User1, user_id=User1.id)

session.add(item2)
session.commit()

print("Adding category items complete!")
