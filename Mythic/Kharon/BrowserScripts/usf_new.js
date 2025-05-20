function(task, responses){
    if ( task.status == "processed" ) {
        if ( responses.length > 0 ) {
            const combined = responses.reduce( (prev, cur) => {
                    return prev + cur;
                }, "");
            return {'plaintext': combined};
        }

        return {"plaintext": "No data yet..."}
    } else if ( task.completed ) {
        if ( responses.length > 0 ) {
            const combined = responses.reduce( (prev, cur) => {
                    return prev + cur;
                }, "");
            return {'plaintext': combined};
        }

        return {"plaintext": "No data to display..."}
    } else {
        return {"plaintext": "Not response yet from agent..."}
    }
}