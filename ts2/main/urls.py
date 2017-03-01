from django.conf.urls import include, url
from .views import index_view as iv, offline as ofv, online as onv, sender as sv
urlpatterns = [
    url(r'^$', iv.main_page, name='main_page'),
    url(r'^offline/', include([
        url(r'^$', iv.offline_detector, name='offline_detector'),
        url(r'^upload/', ofv.upload_file, name='upload_file'),
    ])),
    url(r'^online/', include([
        url(r'^$', iv.online_detector, name='online_detector'),
        url(r'^start/', onv.start, name='online_detector_start'),
        url(r'^finish/', onv.finish, name='online_detector_finish'),
        url(r'^download/', onv.download, name='online_detector_download'),
    ])),
    url(r'^sender/', include([
        url(r'^$', iv.packet_sender, name='packet_sender'),
        url(r'^add/', sv.add, name='packet_sender_add'),
    ])),
    url(r'^test/', iv.test, name='test'),
]