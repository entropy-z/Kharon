// ==UserScript==
// @name         Mythic File Listing Beautifier
// @namespace    http://your-namespace/
// @version      1.0
// @description  Beautifies file listing output in Mythic C2 console
// @author       You
// @match        http://localhost:7443/*
// @grant        GM_addStyle
// ==/UserScript==

(function() {
    'use strict';

    // Estilos CSS para a tabela formatada
    GM_addStyle(`
        .file-listing-table {
            font-family: monospace;
            border-collapse: collapse;
            width: 100%;
            margin: 10px 0;
        }
        .file-listing-table th {
            background-color: #2a2a2a;
            color: white;
            text-align: left;
            padding: 4px 8px;
        }
        .file-listing-table td {
            padding: 4px 8px;
            border-bottom: 1px solid #444;
        }
        .file-listing-table tr:nth-child(even) {
            background-color: #1e1e1e;
        }
        .file-listing-warning {
            color: #ff6b6b;
            font-style: italic;
            margin-top: 10px;
        }
    `);

    // Função para parsear os dados binários
    function parseFileListing(data) {
        try {
            // Converter de base64 para ArrayBuffer se necessário
            let buffer;
            if (typeof data === 'string' && data.startsWith('base64:')) {
                const binaryString = atob(data.substring(7));
                buffer = new Uint8Array(binaryString.length);
                for (let i = 0; i < binaryString.length; i++) {
                    buffer[i] = binaryString.charCodeAt(i);
                }
            } else {
                // Assumir que já é um ArrayBuffer ou Uint8Array
                buffer = new Uint8Array(data);
            }

            // Parser simples
            let offset = 0;
            const view = new DataView(buffer.buffer);

            // Ler SubID (1 byte de padding)
            offset += 1; // Pular o padding

            let output = '';
            let remainingBytes = buffer.length - offset;

            // Criar tabela HTML
            let tableHtml = `
                <table class="file-listing-table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Attr</th>
                            <th>Created</th>
                            <th>Modified</th>
                            <th>Accessed</th>
                        </tr>
                    </thead>
                    <tbody>
            `;

            while (remainingBytes > 0) {
                try {
                    // Ler nome do arquivo (string terminada em null)
                    let fileName = '';
                    while (offset < buffer.length && buffer[offset] !== 0) {
                        fileName += String.fromCharCode(buffer[offset]);
                        offset++;
                    }
                    offset++; // Pular o null terminator

                    // Ler atributos (32-bit little endian)
                    const attribute = view.getInt32(offset, true);
                    offset += 4;
                    const attrStr = {
                        0x1: "R",  // READONLY
                        0x2: "H",  // HIDDEN
                        0x4: "S",  // SYSTEM
                        0x10: "D", // DIRECTORY
                        0x20: "A", // ARCHIVE
                        0x40: "N", // DEVICE
                        0x80: "T"  // NORMAL
                    }[attribute & 0xFF] || "?";

                    // Função para ler timestamp
                    const readTime = () => {
                        const day = view.getInt16(offset, true); offset += 2;
                        const month = view.getInt16(offset, true); offset += 2;
                        const year = view.getInt16(offset, true); offset += 2;
                        const hour = view.getInt16(offset, true); offset += 2;
                        const minute = view.getInt16(offset, true); offset += 2;
                        const second = view.getInt16(offset, true); offset += 2;
                        return `${year.toString().padStart(4, '0')}-${month.toString().padStart(2, '0')}-${day.toString().padStart(2, '0')} ${hour.toString().padStart(2, '0')}:${minute.toString().padStart(2, '0')}`;
                    };

                    const createdTime = readTime();
                    const lastAccessTime = readTime();
                    const lastWriteTime = readTime();

                    // Adicionar linha à tabela
                    tableHtml += `
                        <tr>
                            <td>${fileName}</td>
                            <td>${attrStr}</td>
                            <td>${createdTime}</td>
                            <td>${lastWriteTime}</td>
                            <td>${lastAccessTime}</td>
                        </tr>
                    `;

                    remainingBytes = buffer.length - offset;
                } catch (e) {
                    console.error("Error parsing file entry:", e);
                    break;
                }
            }

            tableHtml += `</tbody></table>`;

            if (remainingBytes > 0) {
                tableHtml += `<div class="file-listing-warning">Warning: ${remainingBytes} unparsed bytes remaining</div>`;
            }

            return tableHtml;
        } catch (e) {
            console.error("Error parsing file listing:", e);
            return `<div class="file-listing-warning">Error parsing directory listing: ${e.message}</div>`;
        }
    }

    // Monitorar novas respostas no Mythic
    function observeMythicResponses() {
        // Esta parte depende da estrutura do UI do Mythic
        // Você precisará ajustar conforme a versão do Mythic que está usando
        
        // Opção 1: Observar mutações no DOM
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === 1) { // Element node
                        // Verificar se é um elemento de resposta de task
                        const taskResponses = node.querySelectorAll ? node.querySelectorAll('.task-response') : [];
                        taskResponses.forEach((responseElement) => {
                            // Verificar se é um comando de listagem de arquivos
                            const command = responseElement.querySelector('.task-command')?.textContent;
                            if (command && (command.includes('ls') || command.includes('dir'))) {
                                const contentElement = responseElement.querySelector('.task-response-content');
                                if (contentElement) {
                                    const originalContent = contentElement.textContent;
                                    try {
                                        // Tentar parsear o conteúdo
                                        const parsedContent = parseFileListing(originalContent);
                                        if (parsedContent) {
                                            contentElement.innerHTML = parsedContent;
                                        }
                                    } catch (e) {
                                        console.error("Error processing response:", e);
                                    }
                                }
                            }
                        });
                    }
                });
            });
        });

        // Começar a observar o container principal do Mythic
        const mythicContainer = document.querySelector('#main-content') || document.body;
        observer.observe(mythicContainer, {
            childList: true,
            subtree: true
        });

        console.log("Mythic File Listing Beautifier loaded");
    }

    // Esperar o Mythic carregar
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', observeMythicResponses);
    } else {
        observeMythicResponses();
    }
})();