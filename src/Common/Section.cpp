/* Copyright (C) 2016 Thomas Lübking <thomas.luebking@gmail.com>
                      Erik Quaeghebeur <trojita@equaeghe.nospammail.net>

   This file is part of the Trojita Qt IMAP e-mail client,
   http://trojita.flaska.net/

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of
   the License or (at your option) version 3 or any later version
   accepted by the membership of KDE e.V. (or its successor approved
   by the membership of KDE e.V.), which shall act as a proxy
   defined in Section 14 of version 3 of the license.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "Connection.h"

Common::Section::Section(qint64 begin_pos, qint64 end_pos)
{
    begin = begin_pos;
    end = end_pos;
    span = begin - end;
}

Common::Section::Section(const Section &other)
{
    begin = other.begin;
    end = other.end;
    span = other.span;
}
