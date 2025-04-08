from django.contrib import admin
from django.urls import path
from app.views import *
from django.conf.urls.static import static
from django.conf import settings

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', index, name='index'),
    path('logout/',Logout, name="logout"),
    path('user_logout/',user_logout, name="user_logout"),
    path('user_profile/', user_profile, name="user_profile"),
    path('user_change_password/', user_change_password, name="user_change_password"),
    path('booking_history/', booking_history, name='booking_history'),
    path('manageCategory/', manageCategory, name='manageCategory'),
    path('editCategory/<int:pid>', editCategory, name='editCategory'),
    path('deleteCategory/<int:pid>', deleteCategory, name='deleteCategory'),
    path('managePackageType/', managePackageType, name='managePackageType'),
    path('editPackageType/<int:pid>', editPackageType, name='editPackageType'),
    path('deletePackageType/<int:pid>', deletePackageType, name='deletePackageType'),
    path('reg_member/', reg_member, name="reg_member"),
    path('delete_user/<int:pid>', delete_user, name="delete_user"),
    path('deleteBooking/<int:pid>', deleteBooking, name='deleteBooking'),
    path('addPackage', addPackage, name='addPackage'),
    path('managePackage/', managePackage, name='managePackage'),
    path('deletePackage/<int:pid>', deletePackage, name='deletePackage'),
    path('new_booking/', new_booking, name='new_booking'),
    path('bookingReport/', bookingReport, name='bookingReport'),
    path('regReport/', regReport, name='regReport'),
    path('changePassword', changePassword, name='changePassword'),
    path('editPackage/<int:pid>', editPackage, name='editPackage'),
    path('registration',registration, name="registration"),
    path('login/',user_login, name="user_login"),
    path('apply-booking/<int:pid>/', apply_booking, name="apply_booking"),
    path('booking_detail/<int:pid>/', booking_detail, name="booking_detail"),
    path('payment/', payment_view, name='payment_view'),
    path('payment/success/', payment_success, name='payment_success'),
    path('payment/failure/', payment_failure, name='payment_failure'),
    path('adminlogin/', admin_login, name='adminlogin'),
    path('admin_home/', admin_home, name='admin_home'),
    path('admin/verify-user/', verify_user, name='verify_user'),
    
    path('add_class/',add_class,name="add_class"),
    path('classlist/', class_list, name='classlist'),
    path('trainerclass/',trainer_dashboard , name='trainerclass'),
    path('edit_class/<int:class_id>/', edit_class, name='edit_class'),
    path('delete_class/<int:class_id>/', delete_class, name='delete_class'),
    path('reg_trainer/', reg_trainer, name="reg_trainer"),
    path('trainer_registration',trainer_registration,name='trainer_registration'),
    path('get-users/', get_users, name='get_users'),  # Fetch users
    path('verify_user/', verify_user, name='verify_user'),  # Verify user
    path('verify_trainer/',verify_trainer, name='verify_trainer'),
    path('trainer_login/', trainer_login, name='trainer_login'),
    path('trainer_page/',trainer_dashboard,name="trainer_page"),
    path('delete-user/', delete_user, name='delete_user'),
    path('trainer_registration/', trainer_registration, name='register_trainer'),
    path('delete_trainer/<int:trainer_id>/', delete_trainer, name='delete_trainer'), 
    path('member_attendance/', member_attendance, name='member_attendance'),
    path('mark_attendance/<int:member_id>/<str:status>/', mark_attendance, name='mark_attendance'),
    


]+static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
