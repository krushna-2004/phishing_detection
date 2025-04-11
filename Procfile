web: gunicorn phishing_detector.wsgi --log-file - 
#or works good with external database
web: python manage.py migrate && gunicorn phishing_detector.wsgi
