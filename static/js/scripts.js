// Глобальные скрипты для приложения
document.addEventListener('DOMContentLoaded', function() {
    // Инициализация всплывающих подсказок Bootstrap
    $('[data-toggle="tooltip"]').tooltip();
    
    // Инициализация выпадающих меню
    $('.dropdown-toggle').dropdown();
    
    // Автоматическое скрытие флеш-сообщений через 5 секунд
    setTimeout(function() {
        $('.alert:not(.alert-persistent)').fadeOut('slow');
    }, 5000);
    
    // Подтверждение удаления
    document.querySelectorAll('.delete-confirm').forEach(function(element) {
        element.addEventListener('click', function(e) {
            if (!confirm('Вы уверены, что хотите удалить этот элемент?')) {
                e.preventDefault();
            }
        });
    });
    
    // Активация текущего пункта меню на основе URL
    highlightCurrentNavItem();
    
    // Инициализация дейтпикеров, если они есть
    initDateRangePicker();
    
    // Инициализация валидации форм
    initFormValidation();
});

// Функция для подсветки текущего пункта меню
function highlightCurrentNavItem() {
    const currentPath = window.location.pathname;
    
    // Ищем все ссылки в навигационной панели
    document.querySelectorAll('.navbar-nav .nav-link').forEach(function(link) {
        const href = link.getAttribute('href');
        
        // Если путь ссылки совпадает с текущим путем, добавляем класс active
        if (href === currentPath) {
            link.classList.add('active');
            
            // Если ссылка находится в выпадающем меню, активируем и родительский элемент
            const dropdownParent = link.closest('.dropdown');
            if (dropdownParent) {
                dropdownParent.querySelector('.dropdown-toggle').classList.add('active');
            }
        }
    });
}

// Инициализация валидации форм
function initFormValidation() {
    const forms = document.querySelectorAll('.needs-validation');
    
    Array.from(forms).forEach(function(form) {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            
            form.classList.add('was-validated');
        }, false);
    });
}

// Инициализация диапазона дат
function initDateRangePicker() {
    // Если на странице есть форма парсера новостей
    const newsParserForm = document.getElementById('newsParserForm');
    if (newsParserForm) {
        // Добавляем слушатель изменений для даты начала
        const startDateInput = document.getElementById('startDate');
        const endDateInput = document.getElementById('endDate');
        
        if (startDateInput && endDateInput) {
            // Устанавливаем минимальную дату окончания равной дате начала
            startDateInput.addEventListener('change', function() {
                endDateInput.min = startDateInput.value;
                
                // Если дата окончания раньше даты начала, корректируем
                if (endDateInput.value < startDateInput.value) {
                    endDateInput.value = startDateInput.value;
                }
            });
            
            // Устанавливаем максимальную дату начала равной дате окончания
            endDateInput.addEventListener('change', function() {
                startDateInput.max = endDateInput.value;
                
                // Если дата начала позже даты окончания, корректируем
                if (startDateInput.value > endDateInput.value) {
                    startDateInput.value = endDateInput.value;
                }
            });
        }
    }
}

// Функция для копирования в буфер обмена
function copyToClipboard(text) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    document.body.appendChild(textArea);
    textArea.select();
    document.execCommand('copy');
    document.body.removeChild(textArea);
    
    // Показываем всплывающее уведомление
    const toast = document.createElement('div');
    toast.className = 'copy-toast';
    toast.textContent = 'Скопировано в буфер обмена!';
    document.body.appendChild(toast);
    
    setTimeout(function() {
        toast.className += ' copy-toast-show';
    }, 10);
    
    setTimeout(function() {
        toast.className = toast.className.replace('copy-toast-show', '');
        setTimeout(function() {
            document.body.removeChild(toast);
        }, 300);
    }, 2000);
}

// Функция для сортировки таблиц
function sortTable(table, column, type = 'string') {
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    
    // Определяем направление сортировки
    const direction = table.getAttribute('data-sort-direction') === 'asc' ? -1 : 1;
    table.setAttribute('data-sort-direction', direction === 1 ? 'asc' : 'desc');
    
    // Сортируем строки
    rows.sort(function(a, b) {
        let aValue = a.cells[column].textContent.trim();
        let bValue = b.cells[column].textContent.trim();
        
        if (type === 'number') {
            aValue = parseFloat(aValue) || 0;
            bValue = parseFloat(bValue) || 0;
            return direction * (aValue - bValue);
        } else if (type === 'date') {
            aValue = new Date(aValue).getTime() || 0;
            bValue = new Date(bValue).getTime() || 0;
            return direction * (aValue - bValue);
        } else {
            return direction * aValue.localeCompare(bValue);
        }
    });
    
    // Перемещаем строки в правильном порядке
    rows.forEach(function(row) {
        tbody.appendChild(row);
    });
}

// Функция экспорта таблицы в CSV
function exportTableToCSV(table, filename) {
    const rows = Array.from(table.querySelectorAll('tr'));
    let csv = [];
    
    rows.forEach(function(row) {
        const cols = Array.from(row.querySelectorAll('td, th'));
        const rowData = cols.map(col => {
            // Очищаем данные от кавычек и обрамляем их кавычками
            let data = col.textContent.trim().replace(/"/g, '""');
            return `"${data}"`;
        });
        csv.push(rowData.join(','));
    });
    
    // Скачивание файла
    const csvContent = csv.join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    
    link.setAttribute('href', url);
    link.setAttribute('download', filename || 'export.csv');
    link.style.visibility = 'hidden';
    
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// Функция для фильтрации таблицы
function filterTable(input, table) {
    const term = input.value.toLowerCase();
    const rows = table.querySelectorAll('tbody tr');
    
    rows.forEach(function(row) {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(term) ? '' : 'none';
    });
} 