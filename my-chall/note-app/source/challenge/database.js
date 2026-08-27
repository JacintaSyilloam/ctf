const sqlite = require('sqlite-async');

class Database {
	constructor(db_file) {
		this.db_file = db_file;
		this.db = undefined;
	}
	
	async connect() {
		this.db = await sqlite.open(this.db_file);
	}

	async migrate() {
		return this.db.exec(`
            DROP TABLE IF EXISTS note;

            CREATE TABLE IF NOT EXISTS note (
                id        VARCHAR(255) NOT NULL PRIMARY KEY,
                value     TEXT NOT NULL
            );
        `);
	}

	async newNote(id, note) {
		return new Promise(async (resolve, reject) => {
			try {
				let stmt = await this.db.prepare('INSERT INTO note (id, value) VALUES ( ?, ? )');
				resolve((await stmt.run(id, note)));
			} catch(e) {
				reject(e);
			}
		});
	}

	async getNote(id) {
		return new Promise(async (resolve, reject) => {
			try {
				let stmt = await this.db.prepare('SELECT value FROM note WHERE id = ?');
				resolve(await stmt.get(id));
			} catch(e) {
				reject(e);
			}
		});
	}

}

module.exports = Database;