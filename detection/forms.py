from django import forms
from .models import URLCheck

class URLCheckForm(forms.ModelForm):
    class Meta:
        model = URLCheck
        fields = ['url']
