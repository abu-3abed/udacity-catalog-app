# udacity-catalog-app
Catalog App project 


Installation
============
This script works only on Python 3.
you can make a clone of this project with this command

	git clone https://github.com/abu-3abed/udacity-catalog-app.git
or you can download it manually by pressing 'Clone or download' and then 'Download ZIP'.

after installing project you have to install **Flask** and **passlib** using pip package manager by entering this in your command line:

	pip install flask
  
previous code will install **Flask** for you. To install **passlib** enter this command:

	pip install passlib
	
for more information on **Flask** framework and **passlib** Python library, look through their documentation from [here](http://flask.pocoo.org/docs/1.0/) and [here](https://passlib.readthedocs.io/en/stable/index.html) respectively.

running project
===============

after installing the project, Flask and passlib you can run the project by running 'project.py' file from cmd or bash.  run this command on the project directory:

	python project.py

app does contain test data in the db. to generate a clean db, delete the current db and run this command:

	python database_setup.py
  
to bring back the initial data enter this command:
 
	python lotsofitems.py
  

Happy coding!!
