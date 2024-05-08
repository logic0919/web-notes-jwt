// 总结:用户的信息通过 Token 字符串的形式，保存在客户端浏览器中。服务器通过还原 Token 字符串的形式来认证用户的身份
// JWT 通常由三部分组成，分别是 Header(头部)、Payload(有效荷载)、Signature(签名),三者之间使用英文的“.”分隔
// Payload 部分才是真正的用户信息，它是用户信息经过加密之后生成的字符串。
// Header 和 Signature 是安全性相关的部分，只是为了保证 Token 的安全性

//  npm install jsonwebtoken express - jwt
// jsonwebtoken 用于生成 JWT 字符串
// express - jwt 用于将JWT 字符串解析还原成 JSON 对象

// 导入 express 模块
const express = require('express')
// 创建 express 的服务器实例
const app = express()

// TODO_01：安装并导入 JWT 相关的两个包，分别是 jsonwebtoken 和 express-jwt(npm i express-jwt@5.3.3)
const jwt = require('jsonwebtoken')
const expressJWT = require('express-jwt')

// 允许跨域资源共享
const cors = require('cors')
app.use(cors())

// 解析 post 表单数据的中间件
const bodyParser = require('body-parser')
app.use(bodyParser.urlencoded({ extended: false }))

// TODO_02：定义 secret 密钥，建议将密钥命名为 secretKey
// 为了保证JWT 字符串的安全性，防止JWT 字符串在网络专输过程中被别人破解，我们需要专门定义一个用于加密和解密的 secret 密钥:
// 当生成JWT字符串的时候，需要使用secret 密钥对户的信息进行加密，最终得到加密好的JWT 字符串
// 当把JWT字符串解析还原成JSON对象的时候，需要使用secret密钥进行解密
// secret 密钥的本质: 就是一个字符串
const secretKey = 'itheima No1 ^_^'

// TODO_04：注册将 JWT 字符串解析还原成 JSON 对象的中间件
// 注意：只要配置成功了 express-jwt 这个中间件，就可以把解析出来的用户信息，挂载到 req.user 属性上
// 只要身份认证成，就会多出req.user这个属性
// 访问以'/api'开头的路径不需要进行身份认证
app.use(expressJWT({ secret: secretKey }).unless({ path: [/^\/api\//] }))

// 登录接口
app.post('/api/login', function (req, res) {
    // 将 req.body 请求体中的数据，转存为 userinfo 常量
    const userinfo = req.body
    // 登录失败
    if (userinfo.username !== 'admin' || userinfo.password !== '000000') {
        return res.send({
            status: 400,
            message: '登录失败！',
        })
    }
    // 登录成功
    // TODO_03：在登录成功之后，调用 jwt.sign() 方法生成 JWT 字符串。并通过 token 属性发送给客户端
    // 参数1：用户的信息对象
    // 参数2：加密的秘钥
    // 参数3：配置对象，可以配置当前 token 的有效期
    // 记住：千万不要把密码加密到 token 字符串中
    const tokenStr = jwt.sign({ username: userinfo.username }, secretKey, { expiresIn: '30s' })
    res.send({
        status: 200,
        message: '登录成功！',
        token: tokenStr, // 要发送给客户端的 token 字符串
    })
})

// 这是一个有权限的 API 接口
app.get('/admin/getinfo', function (req, res) {
    // TODO_05：使用 req.user 获取用户信息，并使用 data 属性将用户信息发送给客户端
    console.log(req.user)
    res.send({
        status: 200,
        message: '获取用户信息成功！',
        data: req.user, // 要发送给客户端的用户信息
    })
})

// TODO_06：使用全局错误处理中间件，捕获解析 JWT 失败后产生的错误
app.use((err, req, res, next) => {
    // 这次错误是由 token 解析失败导致的
    if (err.name === 'UnauthorizedError') {
        return res.send({
            status: 401,
            message: '无效的token',
        })
    }
    res.send({
        status: 500,
        message: '未知的错误',
    })
})

// 调用 app.listen 方法，指定端口号并启动web服务器
app.listen(8888, function () {
    console.log('Express server running at http://127.0.0.1:8888')
})
