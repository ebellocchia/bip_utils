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
from typing import Any, Optional
from bip_utils.ecc.ikeys import IPoint


class DummyPoint(IPoint):
    """ Dummy point class. """

    def __init__(self,
                 x: int,
                 y: int,
                 order: Optional[int] = None) -> None:
        """ Construct class from point coordinates.

        Args:
            x (int): X coordinate
            y (int): Y coordinate
            order (int): Order
        """
        self.m_x = x
        self.m_y = y
        self.m_order = order or 0

    def UnderlyingObject(self) -> Any:
        """ Get the underlying object.

        Returns:
           Any: Underlying object
        """
        pass

    def Order(self) -> int:
        """ Return the point order.

        Returns:
            int: Point order
        """
        return self.m_order

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

    def __add__(self,
                point: IPoint) -> IPoint:
        """ Add point to another point.

        Args:
            point (IPoint object): IPoint object

        Returns:
            IPoint object: IPoint object
        """

        # Not needed
        pass

    def __radd__(self,
                 point: IPoint) -> IPoint:
        """ Add point to another point.

        Args:
            point (IPoint object): IPoint object

        Returns:
            IPoint object: IPoint object
        """

        # Not needed
        pass

    def __mul__(self,
                scalar: int) -> IPoint:
        """ Multiply point by a scalar.

        Args:
            scalar (int): scalar

        Returns:
            IPoint object: IPoint object
        """

        # Not needed
        pass

    def __rmul__(self,
                 scalar: int) -> IPoint:
        """ Multiply point by a scalar.

        Args:
            scalar (int): scalar

        Returns:
            IPoint object: IPoint object
        """

        # Not needed
        pass
