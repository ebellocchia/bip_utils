# Copyright (c) 2021 Emanuele Bellocchia
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


# Imports
from typing import Any
from bip_utils.ecc.ikeys import IPoint
from bip_utils.utils import DataBytes


class DummyPoint(IPoint):
    """ Dummy point class. """

    @classmethod
    def FromBytes(cls,
                  point_bytes: bytes) -> IPoint:
        """ Construct class from point bytes.

        Args:
            point_bytes (bytes): Point bytes

        Returns:
            IPoint: IPoint object
        """
        pass

    @classmethod
    def FromCoordinates(cls,
                        x: int,
                        y: int) -> IPoint:
        """ Construct class from point coordinates.

        Args:
            x (int): X coordinate of the point
            y (int): Y coordinate of the point

        Returns:
            IPoint: IPoint object
        """
        return cls((x, y))

    def __init__(self,
                 point_obj: Any) -> None:
        """ Construct class from point object.

        Args:
            point_obj (class): Point object

        Raises:
            TypeError: If point object is not of the correct type
        """
        if not isinstance(point_obj, tuple):
            raise TypeError("Invalid point object type")
        self.m_x = point_obj[0]
        self.m_y = point_obj[1]

    def UnderlyingObject(self) -> Any:
        """ Get the underlying object.

        Returns:
           Any: Underlying object
        """
        pass

    def X(self) -> int:
        """ Get point X coordinate.

        Returns:
           int: Point X coordinate
        """
        return self.m_x

    def Y(self) -> int:
        """ Get point Y coordinate.

        Returns:
           int: Point Y coordinate
        """
        return self.m_y

    def Raw(self) -> DataBytes:
        """ Return the point encoded to raw bytes.

        Returns:
            DataBytes object: DataBytes object
        """
        pass

    def __add__(self,
                point: IPoint) -> IPoint:
        """ Add point to another point.

        Args:
            point (IPoint object): IPoint object

        Returns:
            IPoint object: IPoint object
        """
        pass

    def __radd__(self,
                 point: IPoint) -> IPoint:
        """ Add point to another point.

        Args:
            point (IPoint object): IPoint object

        Returns:
            IPoint object: IPoint object
        """
        pass

    def __mul__(self,
                scalar: int) -> IPoint:
        """ Multiply point by a scalar.

        Args:
            scalar (int): scalar

        Returns:
            IPoint object: IPoint object
        """
        pass

    def __rmul__(self,
                 scalar: int) -> IPoint:
        """ Multiply point by a scalar.

        Args:
            scalar (int): scalar

        Returns:
            IPoint object: IPoint object
        """
        pass
