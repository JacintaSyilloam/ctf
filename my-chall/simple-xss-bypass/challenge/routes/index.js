const express        = require('express');
const router         = express.Router();
const uid            = require('../helper/uid');
const url_handler    = require('../helper/url_handler');
const bot            = require('../helper/bot');

let db;

const response = data => ({ message: data });

router.get('/', (req, res) => {
	return res.render('index.html');
});

// Admin dashboard route
router.get('/admin', (req, res) => {
    if (req.cookies && req.cookies['secure-cookie'] === 'bd9ba949ba8c9a6aea33bf36b5a4f582') {
        return res.render('admin.html');
    } else {
        return res.status(403).send('Forbidden: Admin access required');
    }
});

router.get('/:id', (req, res) => {
    try {
        db.getNote(req.params.id)
        .then((data) => {
            if (data) {
                return res.render('note.html');
            }
            return res.status(404).send(response('404 page not found'));
        })
        .catch(() => res.status(404).send(response('An error occurred')));
    } catch (error) {
        return res.status(500).send(response('Internal server error'));
    }
})

router.get('/api/note/:id', (req, res) => {
    try {
        db.getNote(req.params.id)
        .then((data) => {
            if (data) {
                const note = url_handler.makeHyperLink(data.value);
                return res.send({
                    "value": note
                });
            }
            return res.status(404).send(response('404 page not found'));
        })
        .catch(() => res.status(404).send(response('An error occurred')));
    } catch (error) {
        return res.status(500).send(response('Internal server error'));
    }
})

router.post('/api/report', async (req, res) => {
    try {
        const { id } = req.body;
        if (id) {
            await bot.reportNote(id)
            .then(() => res.send({
                "message": "Message reported. Admin will check it soon.",
                "success": "true"
            }))
            .catch(() => res.status(404).send(response('An error occurred')));
        } else {
            return res.status(401).send(response('Please fill out all the required fields!'));
        }
    } catch (error) {
        return res.status(500).send(response('Internal server error'));
    }
})

router.post('/', async (req, res) => {
    try {
        const { note } = req.body;

        if (note) {
            const id = uid.generate();
            return db.newNote(id, note)
                .then(() => res.send({ id: id }))
                .catch(() => res.send(response('Something went wrong!')));
        }
        return res.status(401).send(response('Please fill out all the required fields!'));
    } catch (error) {
        return res.status(500).send(response('Internal server error'));
    }
});

module.exports = database => { 
	db = database;
	return router;
};