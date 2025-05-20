function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(task.completed){
        if(responses.length > 0){
            try{
                let data = JSON.parse(responses[0]);
                let headers = [
                    {"plaintext": "Field", "type": "string", "width": 150, "fillWidth": false},
                    {"plaintext": "Value", "type": "string", "fillWidth": true}
                ];
                
                let rows = [];
                // Add all the fields to the table
                for (const [key, value] of Object.entries(data)) {
                    let row = {
                        "Field": {"plaintext": key},
                        "Value": {"plaintext": value?.toString() || "N/A"}
                    };
                    rows.push(row);
                }
                
                rows = rows.map(row => {
                    if (row.Field.plaintext.includes("Start") || 
                        row.Field.plaintext.includes("End") || 
                        row.Field.plaintext.includes("Heap") || 
                        row.Field.plaintext.includes("Gdt")) {
                        row.Value.cellStyle = {"backgroundColor": "rgba(255, 255, 0, 0.1)"};
                    }
                    if (row.Field.plaintext.includes("Elevate") || 
                        row.Field.plaintext.includes("Mask") || 
                        row.Field.plaintext.includes("ProcAch")) {
                        row.Value.cellStyle = {"backgroundColor": "rgba(255, 0, 0, 0.1)"};
                    }
                    return row;
                });
                
                return {
                    "table": [{
                        "headers": headers,
                        "rows": rows,
                        "title": "Agent Details",
                        "styles": {
                            "table": {
                                "border": "1px solid #ccc",
                                "width": "100%"
                            },
                            "header": {
                                "backgroundColor": "#f5f5f5",
                                "fontWeight": "bold"
                            }
                        }
                    }]
                };
            }catch(error){
                const combined = responses.reduce( (prev, cur) => {
                    return prev + cur;
                }, "");
                return {'plaintext': combined};
            }
        }else{
            return {"plaintext": "No data to display..."};
        }
    }else if(task.status === "processed"){
        return {"plaintext": "Processing data..."};
    }else{
        return {"plaintext": "No response yet from agent..."};
    }
}