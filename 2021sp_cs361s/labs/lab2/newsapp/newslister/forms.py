from django import forms
from django.contrib.auth.models import User
from .models import NewsListing
from .models import NewsListing, UserXtraAuth
from django.core.exceptions import ValidationError

class UpdateUserForm(forms.Form):
    update_user_select = forms.ModelChoiceField(
        label="Username",
        queryset = User.objects.filter(is_superuser=False))
    update_user_secrecy  = forms.IntegerField(label="Secrecy Level")
    
    update_user_token    = forms.CharField(label="Token ID", required=False)
    
    def clean(self):
        # STUDENT TODO
        # This is where the "update user" form is validated.
        # The "cleaned_data" is a dictionary with the data
        # entered from the POST request. So, for example,
        # cleaned_data["update_user_secrecy"] returns that
        # form value. You need to update this method to
        # enforce the security policies related to tokens
        # and secrecy.
        # Raise a "ValidationError(<err msg>)" if something 
        # is wrong
        
        cleaned_data = super().clean()

        # raises validation error if the superuser is trying to change
        # the user's securtiy clearance to be lower
        cur_user = UserXtraAuth.objects.get(username=cleaned_data["update_user_select"])
        cur_secrecy = cur_user.secrecy
        if (cleaned_data["update_user_secrecy"] < cur_secrecy):
        	raise ValidationError('Cannot lower user security clearance')

        return cleaned_data
        
class CreateNewsForm(forms.Form):
    new_news_query = forms.CharField(label="New Query", required=False)
    new_news_sources = forms.CharField(label="Sources", required=False)
    new_news_secrecy = forms.IntegerField(label="Secrecy Level", required=False)

    def __init__(self, *args, **kargs):
        super().__init__(*args, **kargs)
        self.user_secrecy = 0
    
    def clean(self):
        # STUDENT TODO
        # This is where newslisting update form is validated.
        # The "cleaned_data" is a dictionary with the data
        # entered from the POST request. So, for example,
        # cleaned_data["new_news_query"] returns that
        # form value. You need to update this method to
        # enforce the security policies related to tokens
        # and secrecy.
        # Return a "ValidationError(<err msg>)" if something 
        # is wrong
        cleaned_data = super().clean()

        # if trying to write down, raise validation error
        # cur_user = UserXtraAuth.objects.get(User.username)

        print("USER SECRECY: " + str(self.user_secrecy))
        print("QUERY SECRECY: " + str(cleaned_data["new_news_secrecy"]))

        if cleaned_data["new_news_secrecy"] < self.user_secrecy:
            print("***VALIDATION ERROR***")
            raise ValidationError('Cannot create a form above your secrecy level')

        print("CLEANED DATA: ")
        print(cleaned_data)

        print("***NO ERROR***")
        return cleaned_data
        
class UpdateNewsForm(forms.Form):
    update_news_select = forms.ModelChoiceField(
        label="Update News",
        queryset=None,
        required=False)
    update_news_query   = forms.CharField(label="Update Query", required=False)
    update_news_sources = forms.CharField(label="Update Sources", required=False)
    update_news_secrecy = forms.IntegerField(label="Update Secrecy", required=False)
    
    def __init__(self, uns, secrecy, *args, **kargs):
        super().__init__(*args, **kargs)
        self.fields['update_news_select'].queryset = uns
        self.user_secrecy = secrecy
        # STUDENT TODO
        # you should change the "queryset" in update_news_select to be None.
        # then, here in the constructor, you can change it to be the filtered
        # data passed in. See this page:
        # https://docs.djangoproject.com/en/3.1/ref/forms/fields/
        # Look specifically in the section "Fields which handle relationships¶"
        # where it talks about starting with an empty queryset.
        #
        # This form is constructed in views.py. Modify this constructor to
        # accept the passed-in (filtered) queryset.
    
    def clean(self):
        cleaned_data = super().clean()
        # STUDENT TODO
        # This is where newslisting update form is validated.
        # The "cleaned_data" is a dictionary with the data
        # entered from the POST request. So, for example,
        # cleaned_data["new_news_query"] returns that
        # form value. You need to update this method to
        # enforce the security policies related to tokens
        # and secrecy.
        # Return a "ValidationError(<err msg>)" if something 
        # is wrong

        if (cleaned_data["data_news_secrecy"] < self.user_secrecy):
        	raise ValidationError('Cannot edit a form above your secrecy level')
        
        return cleaned_data
