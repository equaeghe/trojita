/* Copyright (C) 2007 - 2012 Jan Kundrát <jkt@flaska.net>

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or version 3 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING.  If not, write to
   the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.
*/


#include "IdTask.h"
#include <QCoreApplication>
#include "GetAnyConnectionTask.h"
#include "Model.h"
#include "Utils.h"

namespace Imap
{
namespace Mailbox
{

IdTask::IdTask(Model *_model, ImapTask *dependingTask) : ImapTask(_model)
{
    dependingTask->addDependentTask(this);
    parser = dependingTask->parser;
}

void IdTask::perform()
{
    markAsActiveTask();

    IMAP_TASK_CHECK_ABORT_DIE;

    if (model->property("trojita-imap-enable-id").toBool()) {
        QMap<QByteArray,QByteArray> identification;
        identification["name"] = "Trojita";
        identification["version"] = QCoreApplication::applicationVersion().toAscii();
        identification["os"] = systemPlatformVersion().toAscii();
        tag = parser->idCommand(identification);
    } else {
        tag = parser->idCommand();
    }
}

bool IdTask::handleStateHelper(const Imap::Responses::State *const resp)
{
    if (resp->tag.isEmpty())
        return false;

    if (resp->tag == tag) {
        if (resp->kind == Responses::OK) {
            // nothing should be needed here
            _completed();
        } else {
            _failed("ID failed, strange");
            // But hey, we can just ignore this one
        }
        return true;
    } else {
        return false;
    }
}

bool IdTask::handleId(const Responses::Id *const resp)
{
    model->m_idResult = resp->data;
    return true;
}

}
}
