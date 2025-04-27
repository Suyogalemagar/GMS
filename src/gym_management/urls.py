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
    path('enrolled_history/', enrolled_history, name='enrolled_history'),
    path('manageCategory/', manageCategory, name='manageCategory'),
    path('editCategory/<int:pid>', editCategory, name='editCategory'),
    path('deleteCategory/<int:pid>', deleteCategory, name='deleteCategory'),
    path('managePackageType/', managePackageType, name='managePackageType'),
    path('editPackageType/<int:pid>', editPackageType, name='editPackageType'),
    path('deletePackageType/<int:pid>', deletePackageType, name='deletePackageType'),
    path('reg_member/', reg_member, name="reg_member"),
    path('delete_user/<int:pid>', delete_user, name="delete_user"),
    path('deleteenrolled/<int:pid>', deleteenrolled, name='deleteenrolled'),
    path('addPackage', addPackage, name='addPackage'),
    path('managePackage/', managePackage, name='managePackage'),
    path('deletePackage/<int:pid>', deletePackage, name='deletePackage'),
    path('new_enrolled/', new_enroll, name='new_enrolled'),
    path('enrolledReport/', enrolledReport, name='enrolledReport'),
    path('regReport/', regReport, name='regReport'),
    path('changePassword', changePassword, name='changePassword'),
    path('editPackage/<int:pid>', editPackage, name='editPackage'),
    path('registration',registration, name="registration"),
    path('login/',user_login, name="user_login"),
    path('apply-enrolled/<int:pid>/', apply_enrolled, name="apply_enrolled"),
    path('enrolled_detail/<int:pid>/', enrolled_detail, name="enrolled_detail"),
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
    path('attendance_report/', attendance_report, name='attendance_report'),
    path('send_notification/', send_notification, name='send_notification'),
    path('member/my-classes/', member_classes, name='my_classes'),
    path('member/enrolled-plans/', enrolled_plans, name='enrolled_plans')


   

]+static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
