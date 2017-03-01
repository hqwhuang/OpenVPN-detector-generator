from channels.staticfiles import StaticFilesConsumer
from channels import include
from channels.routing import route
from . import consumers

channel_routing = [
    # This makes Django serve static files from settings.STATIC_URL, similar
    # to django.views.static.serve. This isn't ideal (not exactly production
    # quality) but it works for a minimal example.
    # 'http.request': StaticFilesConsumer(),

    # Wire up websocket channels to our consumers:
    # 'websocket.connect': consumers.ws_connect,
    # 'websocket.receive': consumers.ws_receive,
    # 'websocket.disconnect': consumers.ws_disconnect,
    include([
        route("websocket.connect", consumers.ws_connect),
        route("websocket.receive", consumers.ws_receive),
        route("websocket.disconnect", consumers.ws_disconnect),
    ], path=r"/online_detector"),

    include([
        route("websocket.connect", consumers.sd_connect),
        route("websocket.receive", consumers.sd_receive),
        route("websocket.disconnect", consumers.sd_disconnect),
    ], path=r"/sender"),
]