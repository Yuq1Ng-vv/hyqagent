// Sample JavaScript file for parser testing
import { useState, useEffect } from "react";
import axios from "axios";

function getUser(id) {
    return fetch(`/api/users/${id}`);
}

async function createUser(data) {
    const response = await axios.post("/api/users", data);
    return response.data;
}

class UserComponent extends React.Component {
    constructor(props) {
        super(props);
        this.state = { users: [] };
    }

    componentDidMount() {
        this.loadUsers();
    }

    render() {
        return null;
    }
}

const handler = async (req, res) => {
    const users = await db.query("SELECT * FROM users");
    return res.json(users);
};

var foo = () => "bar";

export default UserComponent;
