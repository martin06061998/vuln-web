from quart import Quart, redirect, render_template, request

from defination import CSP_POLICICY
from middleware.filter import FilterMiddleware
from middleware.httpsecurityheader import HTTPSecurityHeaderMiddleware


app = Quart(__name__)


app.asgi_app = FilterMiddleware(app.asgi_app)
app.asgi_app = HTTPSecurityHeaderMiddleware(app.asgi_app,CSP_POLICICY)


@app.route('/',methods=['GET'])
async def home():
    return redirect('/feedback')


@app.route('/thank_you',methods=['GET'])
async def thank_you():
    first_name = request.args.get('first_name')
    last_name = request.args.get('last_name')
    return await render_template('thank_you.html', first_name=first_name, last_name=last_name)

@app.route('/feedback')
async def feedback_page():
    return await render_template('feedback.html')


@app.route('/feedback', methods=['POST'])
async def insert_feedback():
    data :dict= await request.get_json(force=True, silent=True)
    if data is None:
        return {"msg": "not valid json"}
    from persistence.dal import DAL
    message = data.get('message',None)

    _,msg=await DAL.insert_feedback(message)
    if msg is None:
        msg = "success"
    return {"msg": msg}

@app.route('/feedback/<string:feedback_id>', methods=['GET'])
async def get_feedback_by_id(feedback_id):
    from persistence.dal import DAL
    result,msg=await DAL.get_feedback_by_id(feedback_id)
    if result:
        return {"id":feedback_id,"message":result[0]}
    if msg is None and result is None:
        msg = "Feedback Not found"
    return {"msg": msg}
    
    
if __name__ == "__main__":   
    app.run()