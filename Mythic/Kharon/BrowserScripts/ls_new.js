function(task, responses){
    if(task.status.toLowerCase().includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(task.completed){
        if(responses.length > 0){
            try {
                let data = JSON.parse(responses[0]);
                
                if(data.hasOwnProperty("DirectoryListing")){
                    let items = data["DirectoryListing"];
                    let count = data["Count"] || items.length;
                    
                    const getFileIcon = (name, type) => {
                        if(type === "DIR") return "📁";
                        
                        const extension = name.split('.').pop().toLowerCase();
                        const iconMap = {
                            'txt': '📝', 'pem': '🔐', 'rar': '🗜️', 'zip': '🗜️',
                            'pdf': '📕', 'doc': '📘', 'docx': '📘',
                            'xls': '📊', 'xlsx': '📊', 'csv': '📊',
                            'jpg': '🖼️', 'jpeg': '🖼️', 'png': '🖼️', 'gif': '🖼️',
                            'exe': '⚙️', 'dll': '⚙️', 'sys': '⚙️',
                            '7z': '🗜️', 'mp3': '🎵', 'wav': '🎵', 'ogg': '🎵',
                            'mp4': '🎬', 'avi': '🎬', 'mkv': '🎬',
                            'js': '📜', 'html': '🌐', 'css': '🎨',
                            'py': '🐍', 'java': '☕', 'cpp': '🔧',
                            'ps1': '💻', 'bat': '💻', 'sh': '💻'
                        };
                        return iconMap[extension] || '📄';
                    };

                    const formatSize = (bytes) => {
                        if(bytes === null || bytes === undefined || isNaN(bytes)) return "-";
                        if(bytes === 0) return "0 B";
                        if(bytes < 1024) return bytes + " B";
                        if(bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
                        return (bytes / 1048576).toFixed(1) + " MB";
                    };

                    const formatDate = (dateString) => {
                        if(!dateString) return "-";
                        return dateString;
                    };
                    
                    let table = {
                        "headers": [
                            {"plaintext": "", "type": "string", "width": 30},
                            {"plaintext": "Name", "type": "string", "width": 200},
                            {"plaintext": "Type", "type": "string", "width": 80},
                            {"plaintext": "Size", "type": "string", "width": 100},
                            {"plaintext": "Modified", "type": "string", "width": 200},
                            {"plaintext": "Created", "type": "string", "width": 200},
                            {"plaintext": "Accessed", "type": "string", "width": 200},
                            {"plaintext": "Attributes", "type": "string", "width": 100}
                        ],
                        "rows": []
                    };
                    
                    items.forEach(item => {
                        const icon = getFileIcon(item["Name"], item["Type"]);
                        
                        table.rows.push({
                            "rowStyle": {},
                            "": {"plaintext": icon},
                            "Name": {"plaintext": item["Name"], "copyIcon": true},
                            "Type": {"plaintext": item["Type"]},
                            "Size": {"plaintext": formatSize(item["Size"])},
                            "Modified": {"plaintext": formatDate(item["Modified"])},
                            "Created": {"plaintext": formatDate(item["Created"])},
                            "Accessed": {"plaintext": formatDate(item["Accessed"])},
                            "Attributes": {"plaintext": item["Attributes"] || "-"}
                        });
                    });
                    
                    return {
                        "table": [table],
                        "plaintext": `Total items: ${count}`
                    };
                }
                
            } catch(e) {
                return {"plaintext": responses[0]};
            }
        }else{
            return {"plaintext": "No data to display..."}
        }
    }else if(task.status === "processed"){
        if(responses.length > 0){
            try {
                let data = JSON.parse(responses[0]);
                if(data.hasOwnProperty("DirectoryListing")){
                    return {"plaintext": "Receiving directory listing data..."};
                }
            } catch(e) {
                return {"plaintext": responses[0]};
            }
        }
        return {"plaintext": "No data yet..."}
    }else{
        return {"plaintext": "No response yet from agent..."}
    }
}