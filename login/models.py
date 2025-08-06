from django.db import models

class Gender:
    gender_choices = (
        ("F", "Female"),
        ("M", "Male"),
        ("O", "Others"),
    )
class Authentication(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField(max_length=100, unique=True)
    password = models.CharField(max_length=10)
    gender = models.CharField(
        max_length=1,                        
        choices=Gender.gender_choices,      
        default="O"
    )
    def __str__(self):
        return self.name

    