/* capture_filter_edit.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef CAPTURE_FILTER_EDIT_H
#define CAPTURE_FILTER_EDIT_H

#include <QThread>
#include <QToolButton>
#include "syntax_line_edit.h"

class CaptureFilterSyntaxWorker;
class StockIconToolButton;

class CaptureFilterEdit : public SyntaxLineEdit
{
    Q_OBJECT
public:
    explicit CaptureFilterEdit(QWidget *parent = 0, bool plain = false);

protected:
#if QT_VERSION < QT_VERSION_CHECK(4, 7, 0)
    void paintEvent(QPaintEvent *evt);
#endif
    void resizeEvent(QResizeEvent *);
    void keyPressEvent(QKeyEvent *event) { completionKeyPressEvent(event); }
    void focusInEvent(QFocusEvent *event) { completionFocusInEvent(event); }

public slots:
    void checkFilter();

private slots:
    void initCaptureFilter();
    void applyCaptureFilter();
    void checkFilter(const QString &text);
    void setFilterSyntaxState(QString filter, bool valid, QString err_msg);
    void bookmarkClicked();

private:
    bool plain_;
    bool field_name_only_;
    QString placeholder_text_;
    StockIconToolButton *bookmark_button_;
    StockIconToolButton *clear_button_;
    StockIconToolButton *apply_button_;
    CaptureFilterSyntaxWorker *syntax_worker_;

    void buildCompletionList(const QString& primitive_word);

signals:
    void pushFilterSyntaxStatus(const QString&);
    void popFilterSyntaxStatus();
    void captureFilterSyntaxChanged(bool valid);
    void startCapture();
    void addBookmark(const QString filter);

};

#endif // CAPTURE_FILTER_EDIT_H

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
