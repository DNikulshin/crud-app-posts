import express from 'express'
import jwt from 'jsonwebtoken'
import mongoose from 'mongoose'
import bcrypt from 'bcrypt'
import { validationResult } from 'express-validator'

import { registerValidation } from './validations/auth.js'

import userModal from './models/User.js'

mongoose
    .connect(
        'mongodb+srv://dmn:Valeria09@cluster0.7mljn97.mongodb.net/blog?retryWrites=true&w=majority')
    .then(() => console.log('DB ok'))
    .catch((err) => console.log(err))

const app = express()


app.use(express.json())

app.post('/auth/register', registerValidation, async (req, res) => {
    try {
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).json(errors.array())
        }

        const password = req.body.password

        const sail = await bcrypt.genSalt(10)
        const hash = await bcrypt.hash(password, sail)

        const doc = new userModal({
            email: req.body.email,
            fullName: req.body.fullName,
            avatarUrl: req.body.avatarUrl,
            passwordHash: hash
        })


        const user = await doc.save()

        const token = jwt.sign({ _id: user._id }, 'Valeria09', { expiresIn: '30d' })

        const { passwordHash, ...userData} = user._doc

        res.json({
            ...userData,
            token
        })
    } catch (err) {
        console.log(err)
        res.status(500).json({
            message: 'Не удалось зарегистрироваться!'
        })
    }

})
/*
mongodb+srv://<username>:<password>@cluster0.7mljn97.mongodb.net/?retryWrites=true&w=majority
*/
app.listen(4444, '192.168.1.111', (err) => {
    if (err) {
        console.log(err)
    }
    console.log('Server ok')
})
